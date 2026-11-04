"""Шаг 1: УЦ, сертификаты, ключи, ключ журнала."""

from __future__ import annotations

import datetime as dt
import json

from _common import (
    AUDIT,
    CA_NAME,
    EMPLOYEE,
    HR,
    MANAGER,
    PASSWORDS,
    WORKSPACE,
    fail,
    field,
    line,
    ok,
    paint,
    save_state,
    section,
    short,
    table,
    timed,
    title,
)

from reservix_crypto import audit_chain, gost, keystore, pki

USAGE_NAMES = {
    pki.USAGE_CA: "выпуск сертификатов",
    pki.USAGE_DOCUMENTS: "подпись документов",
    pki.USAGE_AUDIT: "контрольные точки журнала",
}


def main() -> None:
    title("ШАГ 1. Удостоверяющий центр и ключи подписи (ГОСТ Р 34.10-2012)")
    ws = WORKSPACE
    ws.create()
    today = dt.date.today()

    with ws.connect() as conn:
        conn.executemany(
            "INSERT INTO people_employee(id, full_name, position) VALUES (?, ?, ?)",
            [(EMPLOYEE["id"], EMPLOYEE["name"], EMPLOYEE["role"]), (MANAGER["id"], MANAGER["name"], MANAGER["role"])],
        )

        # 1. Корневой сертификат
        section("1. Корневой ключ удостоверяющего центра организации")
        field("Алгоритм", pki.ALGORITHM)
        field("Кривая", f"{gost.CURVE.name}, p = 2²⁵⁶ − 617")
        field("Порядок группы q", short(hex(gost.CURVE.q)[2:], 20))
        root, root_key = pki.create_root(CA_NAME, today)
        pki.save(conn, root)
        pinned = pki.pin_root(ws.trust_dir, root)
        with timed("Шифрование ключа УЦ паролем (PBKDF2, 2000 итераций)"):
            keystore.save(ws.keys_dir, "ca-root", root_key, PASSWORDS["ca-root"])
        field("Серийный номер", root.serial)
        field("Ключ проверки Q = d·P", short(root.public_key, 24))
        field("Отпечаток (Стрибог-256)", short(root.fingerprint, 24))
        field("Срок действия", f"{root.valid_from} — {root.valid_to}")
        ok(f"Корневой сертификат закреплён вне базы данных: {pinned.relative_to(ws.root.parent)}")

        # 2. Сертификаты участников
        section("2. Выпуск сертификатов участникам")
        subjects = [
            (EMPLOYEE, (pki.USAGE_DOCUMENTS,)),
            (HR, (pki.USAGE_DOCUMENTS,)),
            (AUDIT, (pki.USAGE_AUDIT,)),
        ]
        certs: dict[str, pki.Certificate] = {"ca-root": root}
        rows = []
        for subject, usage in subjects:
            private_key = gost.generate_private_key()
            cert = pki.issue(
                root,
                root_key,
                subject_id=subject["subject_id"],
                subject_name=subject["name"],
                subject_role=subject["role"],
                public_key=gost.public_key(private_key),
                key_usage=usage,
                valid_from=today,
            )
            pki.save(conn, cert)
            keystore.save(ws.keys_dir, subject["owner"], private_key, PASSWORDS[subject["owner"]])
            certs[subject["owner"]] = cert
            rows.append(
                [
                    subject["name"],
                    cert.serial,
                    short(cert.public_key, 8),
                    ", ".join(USAGE_NAMES[u] for u in usage),
                    f"до {cert.valid_to}",
                ]
            )
        table(["Владелец", "Серийный номер", "Ключ проверки", "Назначение", "Срок"], rows)
        for cert in certs.values():
            problems = pki.check(cert, root, at=today.isoformat(), usage=cert.key_usage[0])
            if problems:
                fail(f"{cert.subject_name}: {'; '.join(problems)}")
        ok("Подпись УЦ под каждым сертификатом проверена")

        # 3. Ключ журнала аудита
        section("3. Секретный ключ цепочки журнала аудита")
        hmac_key = audit_chain.generate_key()
        key_file = ws.secrets_dir / "audit_hmac.key"
        key_file.write_text(hmac_key.hex(), encoding="utf-8")
        field("Алгоритм", "HMAC-Стрибог-256 (Р 50.1.113-2016)")
        field("Длина ключа", f"{len(hmac_key) * 8} бит")
        field("Где хранится", "вне базы данных (в Reservix — переменная окружения или HSM)")

    # 4. Как хранится закрытый ключ
    section("4. Закрытый ключ сотрудника на диске — только в зашифрованном виде")
    blob = json.loads(keystore.key_path(ws.keys_dir, EMPLOYEE["owner"]).read_text(encoding="utf-8"))
    for name in ("kdf", "iterations", "salt", "cipher", "iv", "ciphertext", "mac_algorithm", "mac"):
        value = str(blob[name])
        is_hex = all(ch in "0123456789abcdef" for ch in value)
        field(name, short(value, 20) if is_hex and len(value) > 48 else value, 14)

    section("5. Проверка пароля")
    with timed("Выработка ключа из пароля и проверка HMAC"):
        restored = keystore.load(ws.keys_dir, EMPLOYEE["owner"], PASSWORDS[EMPLOYEE["owner"]])
    if gost.encode_public_key(gost.public_key(restored)).hex() == certs[EMPLOYEE["owner"]].public_key:
        ok("Верный пароль: ключ расшифрован, d·P совпадает с ключом в сертификате")
    try:
        keystore.load(ws.keys_dir, EMPLOYEE["owner"], "123456")
        fail("Неверный пароль принят — так быть не должно")
    except keystore.KeyUnlockError as error:
        ok(f"Неверный пароль «123456» отвергнут: {error}")

    save_state(
        {
            "root_serial": root.serial,
            "certificates": {owner: cert.serial for owner, cert in certs.items()},
        }
    )
    print()
    line(paint("Готово. Рабочий каталог: workspace/", "bold"))


if __name__ == "__main__":
    main()
