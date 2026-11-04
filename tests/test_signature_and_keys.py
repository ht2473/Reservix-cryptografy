"""Подпись, ключевые файлы, сертификаты."""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest

from reservix_crypto import gost, keystore, pki

TODAY = dt.date(2026, 11, 4)


@pytest.fixture(scope="module")
def keypair():
    d = gost.generate_private_key()
    return d, gost.encode_public_key(gost.public_key(d))


def test_sign_verify_roundtrip(keypair):
    d, q = keypair
    signature = gost.sign(d, "Акт о стажировке".encode())
    assert len(signature) == 64
    assert gost.verify(q, "Акт о стажировке".encode(), signature)


def test_signature_is_randomized(keypair):
    d, _ = keypair
    assert gost.sign(d, b"x") != gost.sign(d, b"x")


def test_changed_message_rejected(keypair):
    d, q = keypair
    signature = gost.sign(d, b"68 %")
    assert not gost.verify(q, b"100 %", signature)


def test_foreign_key_rejected(keypair):
    d, _ = keypair
    other = gost.encode_public_key(gost.public_key(gost.generate_private_key()))
    assert not gost.verify(other, b"x", gost.sign(d, b"x"))


def test_out_of_range_signature_rejected(keypair):
    _, q = keypair
    zero = bytes(64)
    too_big = gost.CURVE.q.to_bytes(32, "big") * 2
    assert not gost.verify(q, b"x", zero)
    assert not gost.verify(q, b"x", too_big)


def test_point_not_on_curve_rejected(keypair):
    d, q = keypair
    broken = q[:-1] + bytes([q[-1] ^ 1])
    assert not gost.verify(broken, b"x", gost.sign(d, b"x"))


# Хранилище ключей


def test_keystore_roundtrip():
    d = gost.generate_private_key()
    blob = keystore.protect(d, "employee-17", "пароль", iterations=10)
    assert d.to_bytes(32, "big").hex() not in str(blob)
    assert keystore.unlock(blob, "пароль") == d


def test_keystore_wrong_password():
    blob = keystore.protect(gost.generate_private_key(), "employee-17", "пароль", iterations=10)
    with pytest.raises(keystore.KeyUnlockError):
        keystore.unlock(blob, "Пароль")


def test_keystore_tampered_ciphertext():
    blob = keystore.protect(gost.generate_private_key(), "employee-17", "пароль", iterations=10)
    flipped = bytearray.fromhex(blob["ciphertext"])
    flipped[0] ^= 0x01
    blob["ciphertext"] = flipped.hex()
    with pytest.raises(keystore.KeyUnlockError):
        keystore.unlock(blob, "пароль")


def test_keystore_owner_bound():
    """Файл ключа нельзя выдать за ключ другого владельца: имя входит в HMAC."""
    blob = keystore.protect(gost.generate_private_key(), "employee-17", "пароль", iterations=10)
    blob["owner"] = "hr-petrova"
    with pytest.raises(keystore.KeyUnlockError):
        keystore.unlock(blob, "пароль")


def test_kuznechik_ctr_is_involution():
    key, iv = bytes(range(32)), bytes(8)
    data = "персональные данные".encode()
    encrypted = gost.kuznechik_ctr(key, iv, data)
    assert encrypted != data
    assert gost.kuznechik_ctr(key, iv, encrypted) == data


# Сертификаты


@pytest.fixture(scope="module")
def ca():
    return pki.create_root("УЦ", TODAY)


def _issue(ca, usage=(pki.USAGE_DOCUMENTS,), valid_from=TODAY):
    root, root_key = ca
    d = gost.generate_private_key()
    cert = pki.issue(
        root,
        root_key,
        subject_id="employee:17",
        subject_name="Иванов И. И.",
        subject_role="инженер",
        public_key=gost.public_key(d),
        key_usage=usage,
        valid_from=valid_from,
    )
    return cert, d


def test_certificate_valid(ca):
    cert, _ = _issue(ca)
    assert pki.check(cert, ca[0], at=TODAY.isoformat(), usage=pki.USAGE_DOCUMENTS) == []


def test_certificate_json_roundtrip(ca):
    cert, _ = _issue(ca)
    assert pki.Certificate.from_json(cert.to_json()) == cert


def test_certificate_altered_field_rejected(ca):
    cert, _ = _issue(ca)
    forged = dataclasses.replace(cert, subject_name="Петрова А. А.")
    assert "подпись удостоверяющего центра под сертификатом неверна" in pki.check(
        forged, ca[0], at=TODAY.isoformat(), usage=pki.USAGE_DOCUMENTS
    )


def test_certificate_from_other_ca_rejected(ca):
    other = pki.create_root("Чужой УЦ", TODAY)
    cert, _ = _issue(other)
    problems = pki.check(cert, ca[0], at=TODAY.isoformat(), usage=pki.USAGE_DOCUMENTS)
    assert "сертификат выдан не доверенным удостоверяющим центром" in problems


def test_certificate_expired(ca):
    cert, _ = _issue(ca, valid_from=dt.date(2020, 1, 1))
    problems = pki.check(cert, ca[0], at=TODAY.isoformat(), usage=pki.USAGE_DOCUMENTS)
    assert any("не действовал" in p for p in problems)


def test_certificate_wrong_usage(ca):
    cert, _ = _issue(ca, usage=(pki.USAGE_AUDIT,))
    problems = pki.check(cert, ca[0], at=TODAY.isoformat(), usage=pki.USAGE_DOCUMENTS)
    assert any("не предназначен" in p for p in problems)
