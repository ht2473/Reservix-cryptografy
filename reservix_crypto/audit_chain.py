"""Цепочка HMAC для журнала аудита.

В Reservix AuditLog запрещает save()/delete() только на уровне ORM,
прямой SQL это обходит. Здесь у каждой записи есть prev_hash и
chain_hash = HMAC(K, prev_hash || запись), ключ K хранится вне базы.

Удаление хвоста цепочка не видит, для этого подписанные контрольные точки.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import gost, pki
from .reservix import now

GENESIS = "0" * 64

# Поля, которые входят в звено
FIELDS = (
    "id",
    "actor_repr",
    "actor_role",
    "action",
    "severity",
    "object_id",
    "object_repr",
    "message",
    "changes",
    "ip_address",
    "request_path",
    "request_method",
    "created_at",
)

# как _ELEVATED_ACTIONS в apps/audit/services.py
ELEVATED = {
    "delete": "notice",
    "export": "notice",
    "settings": "warning",
    "denied": "warning",
    "login_failed": "warning",
}

KEY_SIZE = 32


def generate_key() -> bytes:
    return gost.random_bytes(KEY_SIZE)


def canonical_record(row: Mapping[str, Any]) -> bytes:
    return pki.canonical({name: row[name] for name in FIELDS})


def link(prev_hash: str, record: bytes, key: bytes | None) -> str:
    """key=None - простой хеш без ключа, только для сравнения в демо."""
    data = bytes.fromhex(prev_hash) + record
    if key is None:
        return gost.streebog256(data).hex()
    return gost.hmac_streebog256(key, data).hex()


def append(
    conn: sqlite3.Connection,
    key: bytes | None,
    *,
    action: str,
    actor_repr: str = "",
    actor_role: str = "",
    object_id: str = "",
    object_repr: str = "",
    message: str = "",
    changes: dict | None = None,
    ip_address: str | None = None,
    request_path: str = "",
    request_method: str = "",
    created_at: str | None = None,
) -> int:
    """Добавляет запись в конец журнала и вычисляет её звено."""
    last = conn.execute("SELECT id, chain_hash FROM audit_auditlog ORDER BY id DESC LIMIT 1").fetchone()
    record: dict[str, Any] = {
        "id": (last["id"] + 1) if last else 1,
        "actor_repr": actor_repr,
        "actor_role": actor_role,
        "action": action,
        "severity": ELEVATED.get(action, "info"),
        "object_id": object_id,
        "object_repr": object_repr,
        "message": message,
        "changes": json.dumps(changes or {}, ensure_ascii=False, sort_keys=True),
        "ip_address": ip_address,
        "request_path": request_path,
        "request_method": request_method,
        "created_at": created_at or now(),
    }
    record["prev_hash"] = last["chain_hash"] if last else GENESIS
    record["chain_hash"] = link(record["prev_hash"], canonical_record(record), key)
    columns = ", ".join(record)
    marks = ", ".join("?" for _ in record)
    conn.execute(f"INSERT INTO audit_auditlog({columns}) VALUES ({marks})", tuple(record.values()))
    return record["id"]


def rebuild(conn: sqlite3.Connection, key: bytes | None) -> None:
    """Пересчёт всех звеньев, используется в атаке."""
    prev = GENESIS
    for row in conn.execute("SELECT * FROM audit_auditlog ORDER BY id").fetchall():
        chain_hash = link(prev, canonical_record(row), key)
        conn.execute(
            "UPDATE audit_auditlog SET prev_hash = ?, chain_hash = ? WHERE id = ?",
            (prev, chain_hash, row["id"]),
        )
        prev = chain_hash


@dataclass
class Issue:
    record_id: int
    text: str


@dataclass
class ChainReport:
    checked: int = 0
    issues: list[Issue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues


def verify(conn: sqlite3.Connection, key: bytes | None) -> ChainReport:
    """Проверяет каждое звено и связь каждой записи с предыдущей."""
    report = ChainReport()
    prev_hash = GENESIS
    prev_id = 0
    for row in conn.execute("SELECT * FROM audit_auditlog ORDER BY id").fetchall():
        report.checked += 1
        if row["id"] != prev_id + 1:
            missing = f"№{prev_id + 1}" if row["id"] == prev_id + 2 else f"№{prev_id + 1}–{row['id'] - 1}"
            report.issues.append(Issue(row["id"], f"перед записью отсутствует {missing}"))
        if row["prev_hash"] != prev_hash:
            report.issues.append(
                Issue(row["id"], "запись не продолжает цепочку: предыдущая запись удалена, вставлена или заменена")
            )
        expected = link(row["prev_hash"], canonical_record(row), key)
        if not gost.equal(bytes.fromhex(expected), bytes.fromhex(row["chain_hash"] or "00")):
            report.issues.append(Issue(row["id"], "звено не совпадает: содержимое записи изменено или запись подделана"))
        prev_hash = row["chain_hash"]
        prev_id = row["id"]
    return report


# Контрольные точки


def make_checkpoint(conn: sqlite3.Connection, cert: pki.Certificate, private_key: int) -> dict:
    """Фиксирует состояние журнала подписью службы аудита."""
    last = conn.execute("SELECT id, chain_hash FROM audit_auditlog ORDER BY id DESC LIMIT 1").fetchone()
    count = conn.execute("SELECT COUNT(*) FROM audit_auditlog").fetchone()[0]
    body = {
        "record_count": count,
        "last_id": last["id"] if last else 0,
        "last_hash": last["chain_hash"] if last else GENESIS,
        "created_at": now(),
        "signer": cert.serial,
    }
    return {**body, "signature": gost.sign(private_key, pki.canonical(body)).hex()}


def export_checkpoint(directory: Path, checkpoint: dict) -> Path:
    path = directory / f"checkpoint-{checkpoint['last_id']:06d}.json"
    path.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def latest_checkpoint(directory: Path) -> dict | None:
    files = sorted(directory.glob("checkpoint-*.json"))
    return json.loads(files[-1].read_text(encoding="utf-8")) if files else None


def verify_checkpoint(conn: sqlite3.Connection, checkpoint: dict, root: pki.Certificate) -> list[str]:
    """Сверяет журнал с подписанной контрольной точкой."""
    problems: list[str] = []
    body = {name: value for name, value in checkpoint.items() if name != "signature"}
    cert = pki.load(conn, checkpoint["signer"])
    if cert is None:
        return ["сертификат службы аудита не найден"]
    problems.extend(pki.check(cert, root, at=checkpoint["created_at"], usage=pki.USAGE_AUDIT))
    if not gost.verify(cert.public_key_bytes, pki.canonical(body), bytes.fromhex(checkpoint["signature"])):
        problems.append("подпись контрольной точки неверна")
        return problems

    row = conn.execute("SELECT chain_hash FROM audit_auditlog WHERE id = ?", (checkpoint["last_id"],)).fetchone()
    if row is None:
        problems.append(f"запись №{checkpoint['last_id']}, закреплённая контрольной точкой, отсутствует: журнал усечён")
    elif row["chain_hash"] != checkpoint["last_hash"]:
        problems.append(f"звено записи №{checkpoint['last_id']} не совпадает с контрольной точкой")
    count = conn.execute("SELECT COUNT(*) FROM audit_auditlog WHERE id <= ?", (checkpoint["last_id"],)).fetchone()[0]
    if count != checkpoint["record_count"]:
        problems.append(f"записей до контрольной точки {count}, а закреплено {checkpoint['record_count']}")
    return problems
