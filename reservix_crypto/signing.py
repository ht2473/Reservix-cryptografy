"""Подпись и проверка документов.

Подписывается не только файл, но и атрибуты документа (id, сотрудник,
назначение подписи и т.д.), поэтому подпись нельзя перенести на другой
документ. Автор - сам сотрудник, согласование - кадровая служба.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from . import gost, pki
from .reservix import CHUNK_SIZE, file_path, now
from .workspace import Workspace

PURPOSE_AUTHOR = "author"
PURPOSE_APPROVAL = "approval"

PURPOSES = {
    PURPOSE_AUTHOR: "Подпись сотрудника",
    PURPOSE_APPROVAL: "Согласование кадровой службы",
}


def _read_chunks(path: Path):
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            yield chunk


def content_digest(path: Path) -> str:
    return gost.streebog256_chunks(_read_chunks(path)).hex()


def signed_attributes(
    document: sqlite3.Row, *, digest: str, purpose: str, signer_serial: str, signed_at: str
) -> bytes:
    """Подписываемые атрибуты в однозначном представлении."""
    return pki.canonical(
        {
            "document": document["public_id"],
            "title": document["title"],
            "kind": document["kind"],
            "employee_id": document["employee_id"],
            "original_name": document["original_name"],
            "size_bytes": document["size_bytes"],
            "content_streebog256": digest,
            "purpose": purpose,
            "signer": signer_serial,
            "signed_at": signed_at,
        }
    )


def policy_problem(document: sqlite3.Row, cert: pki.Certificate, purpose: str) -> str | None:
    """Имеет ли владелец сертификата право на подпись этого вида."""
    if purpose == PURPOSE_AUTHOR and cert.subject_id != f"employee:{document['employee_id']}":
        return "подписант не является сотрудником, к делу которого относится документ"
    if purpose == PURPOSE_APPROVAL and not cert.subject_id.startswith("hr:"):
        return "подписант не относится к кадровой службе"
    if purpose not in PURPOSES:
        return f"неизвестное назначение подписи «{purpose}»"
    return None


def create_signature(
    ws: Workspace,
    conn: sqlite3.Connection,
    document: sqlite3.Row,
    *,
    cert: pki.Certificate,
    private_key: int,
    purpose: str,
    signed_at: str | None = None,
) -> int:
    """Вычисляет подпись и записывает её в базу без проверки политики."""
    signed_at = signed_at or now()
    digest = content_digest(file_path(ws, document))
    payload = signed_attributes(document, digest=digest, purpose=purpose, signer_serial=cert.serial, signed_at=signed_at)
    signature = gost.sign(private_key, payload)
    cursor = conn.execute(
        """
        INSERT INTO documents_signature(document_id, purpose, signer_serial, signed_at, content_digest, signature)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (document["public_id"], purpose, cert.serial, signed_at, digest, signature.hex()),
    )
    return int(cursor.lastrowid)


def sign_document(
    ws: Workspace,
    conn: sqlite3.Connection,
    document: sqlite3.Row,
    *,
    cert: pki.Certificate,
    private_key: int,
    purpose: str,
) -> int:
    """Подписание через интерфейс системы: политика проверяется заранее."""
    problem = policy_problem(document, cert, purpose)
    if problem:
        raise PermissionError(problem)
    return create_signature(ws, conn, document, cert=cert, private_key=private_key, purpose=purpose)


@dataclass
class Verdict:

    signature_id: int
    purpose: str
    signer: str
    signed_at: str
    problems: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.problems


def verify_signature(
    ws: Workspace, conn: sqlite3.Connection, document: sqlite3.Row, row: sqlite3.Row, root: pki.Certificate
) -> Verdict:
    """Проверяет подпись по текущему состоянию файла и атрибутов документа."""
    cert = pki.load(conn, row["signer_serial"])
    verdict = Verdict(
        signature_id=row["id"],
        purpose=row["purpose"],
        signer=cert.subject_name if cert else "неизвестен",
        signed_at=row["signed_at"],
    )

    try:
        actual_digest = content_digest(file_path(ws, document))
    except OSError:
        verdict.problems.append("файл документа недоступен")
        return verdict
    if not gost.equal(bytes.fromhex(actual_digest), bytes.fromhex(row["content_digest"])):
        verdict.problems.append("содержимое файла изменено после подписания")

    if cert is None:
        verdict.problems.append("сертификат подписанта не найден")
        return verdict
    verdict.problems.extend(pki.check(cert, root, at=row["signed_at"], usage=pki.USAGE_DOCUMENTS))
    problem = policy_problem(document, cert, row["purpose"])
    if problem:
        verdict.problems.append(problem)

    payload = signed_attributes(
        document,
        digest=actual_digest,
        purpose=row["purpose"],
        signer_serial=row["signer_serial"],
        signed_at=row["signed_at"],
    )
    if not gost.verify(cert.public_key_bytes, payload, bytes.fromhex(row["signature"])):
        verdict.problems.append("подпись не соответствует документу (проверка по ГОСТ Р 34.10-2012)")
    return verdict


def verify_document(ws: Workspace, conn: sqlite3.Connection, public_id: str, root: pki.Certificate) -> list[Verdict]:
    from .reservix import get

    document = get(conn, public_id)
    rows = conn.execute(
        "SELECT * FROM documents_signature WHERE document_id = ? ORDER BY id", (public_id,)
    ).fetchall()
    return [verify_signature(ws, conn, document, row, root) for row in rows]
