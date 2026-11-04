"""Рабочий каталог демо: SQLite, файлы документов, ключи.

Таблицы повторяют documents_document и audit_auditlog из Reservix,
новые таблицы и поля помечены в схеме. Что лежит вне базы (trust/,
secrets/, keys/, checkpoints/), то "злоумышленник" в демо не трогает.
"""

from __future__ import annotations

import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE people_employee (
    id          INTEGER PRIMARY KEY,
    full_name   TEXT NOT NULL,
    position    TEXT NOT NULL
);

CREATE TABLE documents_document (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id         TEXT NOT NULL UNIQUE,
    title             TEXT NOT NULL,
    kind              TEXT NOT NULL,
    file              TEXT NOT NULL,          -- обезличенное имя на диске
    original_name     TEXT NOT NULL,
    content_type_name TEXT NOT NULL DEFAULT '',
    size_bytes        INTEGER NOT NULL DEFAULT 0,
    checksum          TEXT NOT NULL DEFAULT '', -- SHA-256, как в Reservix
    employee_id       INTEGER REFERENCES people_employee(id),
    uploaded_by       TEXT NOT NULL DEFAULT '',
    access_level      TEXT NOT NULL DEFAULT 'restricted',
    created_at        TEXT NOT NULL
);

-- новое: сертификаты ключей проверки подписи
CREATE TABLE crypto_certificate (
    serial      TEXT PRIMARY KEY,
    subject_id  TEXT NOT NULL,
    body        TEXT NOT NULL               -- сертификат в JSON
);

-- новое: подписи документов
CREATE TABLE documents_signature (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id     TEXT NOT NULL,          -- public_id документа
    purpose         TEXT NOT NULL,          -- author | approval
    signer_serial   TEXT NOT NULL,
    signed_at       TEXT NOT NULL,
    content_digest  TEXT NOT NULL,          -- Стрибог-256 файла
    signature       TEXT NOT NULL           -- r ‖ s, hex
);

CREATE TABLE audit_auditlog (
    id             INTEGER PRIMARY KEY,
    actor_repr     TEXT NOT NULL DEFAULT '',
    actor_role     TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL,
    severity       TEXT NOT NULL DEFAULT 'info',
    object_id      TEXT NOT NULL DEFAULT '',
    object_repr    TEXT NOT NULL DEFAULT '',
    message        TEXT NOT NULL DEFAULT '',
    changes        TEXT NOT NULL DEFAULT '{}',
    ip_address     TEXT,
    request_path   TEXT NOT NULL DEFAULT '',
    request_method TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    prev_hash      TEXT NOT NULL DEFAULT '', -- новое: звено предыдущей записи
    chain_hash     TEXT NOT NULL DEFAULT ''  -- новое: звено этой записи
);
"""


@dataclass(frozen=True)
class Workspace:

    root: Path

    @property
    def db_path(self) -> Path:
        return self.root / "reservix.sqlite3"

    @property
    def media_dir(self) -> Path:
        return self.root / "media"

    @property
    def keys_dir(self) -> Path:
        return self.root / "keys"

    @property
    def trust_dir(self) -> Path:
        return self.root / "trust"

    @property
    def secrets_dir(self) -> Path:
        return self.root / "secrets"

    @property
    def checkpoints_dir(self) -> Path:
        return self.root / "checkpoints"

    @property
    def backup_dir(self) -> Path:
        return self.root / "_backup"

    def exists(self) -> bool:
        return self.db_path.exists()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """commit при успехе, rollback при ошибке, close в любом случае."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create(self) -> None:
        """Создаёт пустой рабочий каталог, удаляя прежний."""
        if self.root.exists():
            shutil.rmtree(self.root)
        for directory in (
            self.media_dir,
            self.keys_dir,
            self.trust_dir,
            self.secrets_dir,
            self.checkpoints_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    # Снимок состояния: атака проводится, затем всё возвращается

    def snapshot(self) -> None:
        """Копия базы и файлов перед атакой."""
        if self.backup_dir.exists():
            shutil.rmtree(self.backup_dir)
        self.backup_dir.mkdir(parents=True)
        shutil.copy2(self.db_path, self.backup_dir / self.db_path.name)
        shutil.copytree(self.media_dir, self.backup_dir / "media")

    def restore(self) -> None:
        """Откат после атаки."""
        shutil.copy2(self.backup_dir / self.db_path.name, self.db_path)
        shutil.rmtree(self.media_dir)
        shutil.copytree(self.backup_dir / "media", self.media_dir)

    def drop_snapshot(self) -> None:
        if self.backup_dir.exists():
            shutil.rmtree(self.backup_dir)
