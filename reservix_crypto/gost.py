"""Примитивы на ГОСТ.

Стрибог, HMAC (Р 50.1.113-2016), PBKDF2 (Р 50.1.111-2016) и Кузнечик берутся
из gostcrypto. Подпись ГОСТ Р 34.10-2012 написана здесь: в gostcrypto она
слишком медленная (минуты на операцию). Проверка - контрольный пример из
приложения А стандарта, см. tests/test_gost_vectors.py.
"""

from __future__ import annotations

import hmac as _hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass

from gostcrypto import gostcipher, gosthash, gosthmac, gostpbkdf, gostsignature

# ГОСТ Р 34.11-2012 «Стрибог»


def streebog256(data: bytes) -> bytes:
    return bytes(gosthash.new("streebog256", data=bytearray(data)).digest())


def streebog512(data: bytes) -> bytes:
    return bytes(gosthash.new("streebog512", data=bytearray(data)).digest())


def streebog256_chunks(chunks: Iterable[bytes]) -> bytes:
    """Хеш-код потока данных: файл читается частями, а не целиком."""
    hasher = gosthash.new("streebog256")
    for chunk in chunks:
        hasher.update(bytearray(chunk))
    return bytes(hasher.digest())


# HMAC (Р 50.1.113-2016) и выработка ключа из пароля (Р 50.1.111-2016)


def hmac_streebog256(key: bytes, data: bytes) -> bytes:
    # gostcrypto затирает переданный ключ, поэтому копия
    return bytes(gosthmac.new("HMAC_GOSTR3411_2012_256", bytearray(key), data=bytearray(data)).digest())


def equal(left: bytes, right: bytes) -> bool:
    """compare_digest, чтобы сравнение не утекало по времени."""
    return _hmac.compare_digest(left, right)


def pbkdf2(password: str, salt: bytes, iterations: int, length: int) -> bytes:
    """Ключ из пароля: PBKDF2 с HMAC-Стрибог-512 по Р 50.1.111-2016."""
    kdf = gostpbkdf.new(bytearray(password.encode("utf-8")), salt=bytearray(salt), counter=iterations)
    return bytes(kdf.derive(length))


def random_bytes(size: int) -> bytes:
    return secrets.token_bytes(size)


# ГОСТ Р 34.12-2015 «Кузнечик», режим гаммирования (CTR) ГОСТ Р 34.13-2015

# IV для CTR у Кузнечика - половина блока
KUZNECHIK_CTR_IV_SIZE = 8


def kuznechik_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """В CTR шифрование и расшифрование - одна операция."""
    if len(key) != 32:
        raise ValueError("Ключ «Кузнечика» — 256 бит")
    if len(iv) != KUZNECHIK_CTR_IV_SIZE:
        raise ValueError("Синхропосылка режима гаммирования — 64 бита")
    cipher = gostcipher.new("kuznechik", bytearray(key), gostcipher.MODE_CTR, init_vect=bytearray(iv))
    return bytes(cipher.encrypt(bytearray(data)))


# ГОСТ Р 34.10-2012: электронная подпись

Point = tuple[int, int] | None  # None — нулевая точка (бесконечно удалённая)


@dataclass(frozen=True)
class Curve:
    """Эллиптическая кривая y² = x³ + ax + b над полем F_p с точкой P порядка q."""

    name: str
    p: int
    a: int
    b: int
    q: int
    x: int
    y: int

    @property
    def size(self) -> int:
        """Длина чисел r, s и координат в байтах (32 для 256-битной подписи)."""
        return (self.q.bit_length() + 7) // 8

    @property
    def base(self) -> tuple[int, int]:
        return (self.x, self.y)

    def contains(self, point: Point) -> bool:
        if point is None:
            return False
        x, y = point
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0


def _curve_from_gostcrypto(name: str) -> Curve:
    params = gostsignature.CURVES_R_1323565_1_024_2019[name]
    return Curve(name, params["p"], params["a"], params["b"], params["q"], params["x"], params["y"])


# 256 бит, paramSetB из Р 1323565.1.024-2019
CURVE = _curve_from_gostcrypto("id-tc26-gost-3410-2012-256-paramSetB")


def point_add(left: Point, right: Point, curve: Curve) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    p = curve.p
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        slope = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, p) % p
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mult(k: int, point: Point, curve: Curve) -> Point:
    """Кратная точка kP методом «удвоение — сложение».

    Время работы зависит от битов k; для учебной демонстрации это допустимо,
    в промышленной реализации нужна лестница Монтгомери.
    """
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend, curve)
        addend = point_add(addend, addend, curve)
        k >>= 1
    return result


def digest_to_int(digest: bytes) -> int:
    """Число α, двоичным представлением которого служит хеш-код.

    Стрибог выдаёт байты в обратном порядке относительно записи вектора
    в стандарте: для сообщения M1 стандарт приводит 00557be5…, библиотека
    возвращает …e5577b5500. Поэтому байты читаются как little-endian.
    """
    return int.from_bytes(digest, "little")


def generate_private_key(curve: Curve = CURVE) -> int:
    """Ключ подписи d — случайное число 0 < d < q."""
    return secrets.randbelow(curve.q - 1) + 1


def public_key(private_key: int, curve: Curve = CURVE) -> tuple[int, int]:
    """Ключ проверки подписи Q = dP."""
    point = scalar_mult(private_key, curve.base, curve)
    assert point is not None
    return point


def sign_digest(private_key: int, digest_value: int, curve: Curve = CURVE, k: int | None = None) -> tuple[int, int]:
    """Формирование подписи, п. 6.1 ГОСТ Р 34.10-2012. Возвращает пару (r, s).

    Параметр ``k`` задаётся только для контрольного примера стандарта:
    повтор k для двух разных сообщений раскрывает ключ подписи.
    """
    q = curve.q
    e = digest_value % q  # шаг 2
    if e == 0:
        e = 1
    while True:
        nonce = k if k is not None else secrets.randbelow(q - 1) + 1  # шаг 3
        point = scalar_mult(nonce, curve.base, curve)  # шаг 4: C = kP
        assert point is not None
        r = point[0] % q
        if r == 0:
            continue
        s = (r * private_key + nonce * e) % q  # шаг 5
        if s == 0:
            continue
        return r, s


def verify_digest(public: tuple[int, int], digest_value: int, signature: tuple[int, int], curve: Curve = CURVE) -> bool:
    """Проверка подписи, п. 6.2 ГОСТ Р 34.10-2012."""
    r, s = signature
    q = curve.q
    if not (0 < r < q and 0 < s < q):  # шаг 1
        return False
    if not curve.contains(public):
        return False
    e = digest_value % q  # шаги 2–3
    if e == 0:
        e = 1
    v = pow(e, -1, q)  # шаг 4
    z1 = s * v % q  # шаг 5
    z2 = -r * v % q
    point = point_add(scalar_mult(z1, curve.base, curve), scalar_mult(z2, public, curve), curve)  # шаг 6
    if point is None:
        return False
    return point[0] % q == r  # шаг 7


# Удобные обёртки над байтами


def encode_public_key(point: tuple[int, int], curve: Curve = CURVE) -> bytes:
    size = curve.size
    return point[0].to_bytes(size, "big") + point[1].to_bytes(size, "big")


def decode_public_key(data: bytes, curve: Curve = CURVE) -> tuple[int, int]:
    size = curve.size
    if len(data) != 2 * size:
        raise ValueError("Неверная длина ключа проверки подписи")
    point = (int.from_bytes(data[:size], "big"), int.from_bytes(data[size:], "big"))
    if not curve.contains(point):
        raise ValueError("Ключ проверки подписи не лежит на кривой")
    return point


def sign(private_key: int, message: bytes, curve: Curve = CURVE) -> bytes:
    """Подпись сообщения: Стрибог-256, затем ГОСТ Р 34.10-2012. Результат r ‖ s."""
    r, s = sign_digest(private_key, digest_to_int(streebog256(message)), curve)
    return r.to_bytes(curve.size, "big") + s.to_bytes(curve.size, "big")


def verify(public: bytes | tuple[int, int], message: bytes, signature: bytes, curve: Curve = CURVE) -> bool:
    """Любая ошибка формата считается неверной подписью."""
    try:
        point = decode_public_key(public, curve) if isinstance(public, bytes) else public
    except ValueError:
        return False
    size = curve.size
    if len(signature) != 2 * size:
        return False
    r = int.from_bytes(signature[:size], "big")
    s = int.from_bytes(signature[size:], "big")
    return verify_digest(point, digest_to_int(streebog256(message)), (r, s), curve)
