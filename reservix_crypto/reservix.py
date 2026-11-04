"""Хранилище документов Reservix без Django.

Перенесено из apps/documents/models.py и apps/documents/services.py
(document_upload_path, compute_checksum, upload, verify_integrity).
Сумма SHA-256 лежит в той же таблице и считается без ключа - на этом
и построены атаки в demo/03_attack_document.py.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import mimetypes
import shutil
import sqlite3
import uuid
from pathlib import Path

from .workspace import Workspace

CHUNK_SIZE = 64 * 1024

DOCUMENT_KINDS = {
    "order": "Приказ",
    "protocol": "Протокол",
    "certificate": "Сертификат",
    "report": "Отчёт",
    "profile": "Профиль должности",
    "plan": "План",
    "statement": "Заявление",
    "other": "Прочее",
}


def now() -> str:
    return dt.datetime.now().replace(microsecond=0).isoformat(sep=" ")


def document_upload_path(filename: str) -> str:
    """Обезличенный путь хранения файла: documents/ГГГГ/ММ/<uuid>.<расширение>."""
    suffix = Path(filename).suffix.lower()
    moment = dt.datetime.now()
    return f"documents/{moment:%Y/%m}/{uuid.uuid4().hex}{suffix}"


def file_path(ws: Workspace, document: sqlite3.Row) -> Path:
    return ws.media_dir / document["file"]


def compute_checksum(path: Path) -> str:
    """SHA-256 содержимого файла, чтение частями по 64 КБ."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def upload(
    ws: Workspace,
    conn: sqlite3.Connection,
    *,
    source: Path,
    title: str,
    kind: str,
    employee_id: int | None,
    uploaded_by: str,
) -> sqlite3.Row:
    """Сохраняет файл в хранилище и регистрирует документ."""
    relative = document_upload_path(source.name)
    target = ws.media_dir / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)

    public_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO documents_document(public_id, title, kind, file, original_name,
            content_type_name, size_bytes, employee_id, uploaded_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            public_id,
            title.strip(),
            kind,
            relative,
            source.name,
            mimetypes.guess_type(source.name)[0] or "",
            target.stat().st_size,
            employee_id,
            uploaded_by,
            now(),
        ),
    )
    # в Reservix сумма тоже считается после сохранения
    conn.execute(
        "UPDATE documents_document SET checksum = ? WHERE public_id = ?",
        (compute_checksum(target), public_id),
    )
    return get(conn, public_id)


def get(conn: sqlite3.Connection, public_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM documents_document WHERE public_id = ?", (public_id,)).fetchone()
    if row is None:
        raise LookupError(f"Документ {public_id} не найден")
    return row


def verify_integrity(ws: Workspace, document: sqlite3.Row) -> bool:
    """Сверяет контрольную сумму файла с сохранённой при приёме."""
    if not document["checksum"]:
        return False
    try:
        return compute_checksum(file_path(ws, document)) == document["checksum"]
    except OSError:
        return False
