"""Упрощённый УЦ: корневой сертификат и сертификаты пользователей.

Без сертификата подпись ничего не доказывает - злоумышленник просто
сделает свою пару ключей. Корневой сертификат лежит в trust/root.json,
а не в базе.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from . import gost

ALGORITHM = "ГОСТ Р 34.10-2012 (256 бит), Стрибог-256, id-tc26-gost-3410-2012-256-paramSetB"

USAGE_CA = "certificate_signing"
USAGE_DOCUMENTS = "document_signing"
USAGE_AUDIT = "audit_checkpoint"


def canonical(data: dict) -> bytes:
    """Однозначное байтовое представление: порядок ключей и пробелы фиксированы."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Certificate:
    serial: str
    subject_id: str
    subject_name: str
    subject_role: str
    public_key: str
    key_usage: tuple[str, ...]
    valid_from: str
    valid_to: str
    issuer_serial: str
    issuer_name: str
    algorithm: str = ALGORITHM
    signature: str = field(default="")

    # Представление

    def to_be_signed(self) -> bytes:
        """Подписываемая часть: все поля, кроме самой подписи."""
        data = asdict(self)
        data.pop("signature")
        data["key_usage"] = list(self.key_usage)
        return canonical(data)

    def to_json(self) -> str:
        data = asdict(self)
        data["key_usage"] = list(self.key_usage)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> Certificate:
        data = json.loads(text)
        data["key_usage"] = tuple(data["key_usage"])
        return cls(**data)

    @property
    def fingerprint(self) -> str:
        """Отпечаток сертификата: Стрибог-256 от полного содержимого."""
        return gost.streebog256(self.to_be_signed() + bytes.fromhex(self.signature)).hex()

    @property
    def public_key_bytes(self) -> bytes:
        return bytes.fromhex(self.public_key)

    def valid_at(self, moment: str) -> bool:
        day = moment[:10]
        return self.valid_from <= day <= self.valid_to


def new_serial() -> str:
    return gost.random_bytes(8).hex()


def _signed(cert: Certificate, issuer_key: int) -> Certificate:
    return replace(cert, signature=gost.sign(issuer_key, cert.to_be_signed()).hex())


def create_root(name: str, valid_from: dt.date, years: int = 10) -> tuple[Certificate, int]:
    """Самоподписанный корневой сертификат УЦ и его ключ подписи."""
    private_key = gost.generate_private_key()
    serial = new_serial()
    cert = Certificate(
        serial=serial,
        subject_id="ca:root",
        subject_name=name,
        subject_role="Удостоверяющий центр",
        public_key=gost.encode_public_key(gost.public_key(private_key)).hex(),
        key_usage=(USAGE_CA,),
        valid_from=valid_from.isoformat(),
        valid_to=valid_from.replace(year=valid_from.year + years).isoformat(),
        issuer_serial=serial,
        issuer_name=name,
    )
    return _signed(cert, private_key), private_key


def issue(
    issuer: Certificate,
    issuer_key: int,
    *,
    subject_id: str,
    subject_name: str,
    subject_role: str,
    public_key: tuple[int, int],
    key_usage: tuple[str, ...],
    valid_from: dt.date,
    years: int = 1,
) -> Certificate:
    """Выпуск сертификата: УЦ подписывает ключ проверки подписи владельца."""
    if USAGE_CA not in issuer.key_usage:
        raise ValueError("Издатель не имеет права выпускать сертификаты")
    cert = Certificate(
        serial=new_serial(),
        subject_id=subject_id,
        subject_name=subject_name,
        subject_role=subject_role,
        public_key=gost.encode_public_key(public_key).hex(),
        key_usage=key_usage,
        valid_from=valid_from.isoformat(),
        valid_to=valid_from.replace(year=valid_from.year + years).isoformat(),
        issuer_serial=issuer.serial,
        issuer_name=issuer.subject_name,
    )
    return _signed(cert, issuer_key)


def check(cert: Certificate, root: Certificate, *, at: str, usage: str) -> list[str]:
    """Возвращает список проблем, пустой - сертификат в порядке."""
    problems: list[str] = []
    if not gost.verify(root.public_key_bytes, root.to_be_signed(), bytes.fromhex(root.signature)):
        problems.append("корневой сертификат повреждён")
    if cert.issuer_serial != root.serial:
        problems.append("сертификат выдан не доверенным удостоверяющим центром")
    elif not gost.verify(root.public_key_bytes, cert.to_be_signed(), bytes.fromhex(cert.signature or "00")):
        problems.append("подпись удостоверяющего центра под сертификатом неверна")
    if not cert.valid_at(at):
        problems.append(f"сертификат не действовал на {at[:10]} (срок {cert.valid_from} — {cert.valid_to})")
    if usage not in cert.key_usage:
        problems.append(f"ключ не предназначен для «{usage}»")
    return problems


# Хранение


def save(conn: sqlite3.Connection, cert: Certificate) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO crypto_certificate(serial, subject_id, body) VALUES (?, ?, ?)",
        (cert.serial, cert.subject_id, cert.to_json()),
    )


def load(conn: sqlite3.Connection, serial: str) -> Certificate | None:
    row = conn.execute("SELECT body FROM crypto_certificate WHERE serial = ?", (serial,)).fetchone()
    return Certificate.from_json(row["body"]) if row else None


def find_by_subject(conn: sqlite3.Connection, subject_id: str) -> Certificate | None:
    row = conn.execute(
        "SELECT body FROM crypto_certificate WHERE subject_id = ? ORDER BY rowid DESC LIMIT 1",
        (subject_id,),
    ).fetchone()
    return Certificate.from_json(row["body"]) if row else None


def pin_root(trust_dir: Path, root: Certificate) -> Path:
    """Закрепляет корневой сертификат вне базы данных."""
    path = trust_dir / "root.json"
    path.write_text(root.to_json(), encoding="utf-8")
    return path


def trusted_root(trust_dir: Path) -> Certificate:
    return Certificate.from_json((trust_dir / "root.json").read_text(encoding="utf-8"))
