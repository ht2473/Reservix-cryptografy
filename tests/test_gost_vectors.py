"""Контрольные примеры из стандартов."""

from __future__ import annotations

from reservix_crypto import gost

# ГОСТ Р 34.11-2012, приложение А, пример 1. В стандарте векторы записаны
# старшим байтом вперёд, поэтому здесь сообщение и хеш-коды перевёрнуты.
M1 = b"012345678901234567890123456789012345678901234567890123456789012"
M1_H256 = bytes.fromhex("00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")[::-1]
M1_H512 = bytes.fromhex(
    "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00"
    "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b"
)[::-1]


def test_streebog256_standard_example():
    assert gost.streebog256(M1) == M1_H256


def test_streebog512_standard_example():
    assert gost.streebog512(M1) == M1_H512


def test_streebog_chunks_equal_whole():
    data = bytes(range(256)) * 300
    chunks = [data[i : i + 4096] for i in range(0, len(data), 4096)]
    assert gost.streebog256_chunks(chunks) == gost.streebog256(data)


def test_hmac_streebog256_r_50_1_113_2016():
    """Р 50.1.113-2016, пример для HMAC_GOSTR3411_2012_256 (он же в RFC 7836)."""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    data = bytes.fromhex("0126bdb87800af214341456563780100")
    expected = bytes.fromhex("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")
    assert gost.hmac_streebog256(key, data) == expected


# ГОСТ Р 34.10-2012, приложение А.1: контрольный пример на тестовой кривой.
TEST_CURVE = gost.Curve(
    name="test",
    p=0x8000000000000000000000000000000000000000000000000000000000000431,
    a=7,
    b=0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E,
    q=0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3,
    x=2,
    y=0x08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8,
)
D = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
Q = (
    0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B,
    0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA,
)
E = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
K = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3
R = 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493
S = 0x01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40


def test_gost3410_test_curve_base_point():
    assert TEST_CURVE.contains(TEST_CURVE.base)


def test_gost3410_public_key_standard_example():
    assert gost.public_key(D, TEST_CURVE) == Q


def test_gost3410_signature_standard_example():
    assert gost.sign_digest(D, E, TEST_CURVE, k=K) == (R, S)


def test_gost3410_verification_standard_example():
    assert gost.verify_digest(Q, E, (R, S), TEST_CURVE)
    assert not gost.verify_digest(Q, E + 1, (R, S), TEST_CURVE)


def test_working_curve_parameters():
    """Рабочая кривая paramSetB: p = 2^256 − 617, базовая точка на кривой, qP = 0."""
    curve = gost.CURVE
    assert curve.p == 2**256 - 617
    assert curve.contains(curve.base)
    assert gost.scalar_mult(curve.q, curve.base, curve) is None
