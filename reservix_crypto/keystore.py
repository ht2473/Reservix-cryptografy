"""Закрытый ключ в файле, зашифрованный паролем.

PBKDF2 даёт 64 байта: половина на Кузнечик (CTR), половина на HMAC.
Сначала шифруем, потом считаем HMAC; при открытии HMAC проверяется
до расшифровки, так что неверный пароль и испорченный файл неотличимы.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import gost

FORMAT = "reservix-key/1"
DEFAULT_ITERATIONS = 2000
SALT_SIZE = 16


class KeyUnlockError(Exception):
    """Неверный пароль или повреждённый файл ключа."""


def _mac_input(owner: str, iterations: int, salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    header = f"{FORMAT}|{owner}|{iterations}".encode()
    return header + salt + iv + ciphertext


def protect(private_key: int, owner: str, password: str, iterations: int = DEFAULT_ITERATIONS) -> dict:
    """Зашифровывает ключ подписи паролем владельца."""
    salt = gost.random_bytes(SALT_SIZE)
    iv = gost.random_bytes(gost.KUZNECHIK_CTR_IV_SIZE)
    material = gost.pbkdf2(password, salt, iterations, 64)
    enc_key, mac_key = material[:32], material[32:]

    plaintext = private_key.to_bytes(gost.CURVE.size, "big")
    ciphertext = gost.kuznechik_ctr(enc_key, iv, plaintext)
    mac = gost.hmac_streebog256(mac_key, _mac_input(owner, iterations, salt, iv, ciphertext))
    return {
        "format": FORMAT,
        "owner": owner,
        "kdf": "PBKDF2-HMAC-Стрибог-512 (Р 50.1.111-2016)",
        "iterations": iterations,
        "salt": salt.hex(),
        "cipher": "Кузнечик, режим гаммирования (ГОСТ Р 34.12-2015, 34.13-2015)",
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "mac_algorithm": "HMAC-Стрибог-256 (Р 50.1.113-2016)",
        "mac": mac.hex(),
    }


def unlock(blob: dict, password: str) -> int:
    """Расшифровывает ключ подписи. Неверный пароль — ``KeyUnlockError``."""
    if blob.get("format") != FORMAT:
        raise KeyUnlockError("Неизвестный формат файла ключа")
    salt = bytes.fromhex(blob["salt"])
    iv = bytes.fromhex(blob["iv"])
    ciphertext = bytes.fromhex(blob["ciphertext"])
    iterations = int(blob["iterations"])

    material = gost.pbkdf2(password, salt, iterations, 64)
    enc_key, mac_key = material[:32], material[32:]
    expected = gost.hmac_streebog256(mac_key, _mac_input(blob["owner"], iterations, salt, iv, ciphertext))
    if not gost.equal(expected, bytes.fromhex(blob["mac"])):
        raise KeyUnlockError("Неверный пароль или файл ключа изменён")

    private_key = int.from_bytes(gost.kuznechik_ctr(enc_key, iv, ciphertext), "big")
    if not 0 < private_key < gost.CURVE.q:
        raise KeyUnlockError("Повреждённое значение ключа")
    return private_key


def key_path(keys_dir: Path, owner: str) -> Path:
    return keys_dir / f"{owner}.key.json"


def save(keys_dir: Path, owner: str, private_key: int, password: str, iterations: int = DEFAULT_ITERATIONS) -> Path:
    path = key_path(keys_dir, owner)
    path.write_text(json.dumps(protect(private_key, owner, password, iterations), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load(keys_dir: Path, owner: str, password: str) -> int:
    blob = json.loads(key_path(keys_dir, owner).read_text(encoding="utf-8"))
    return unlock(blob, password)
