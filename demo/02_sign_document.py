"""Шаг 2: загрузка акта в хранилище и подписание."""

from __future__ import annotations

import json

from _common import (
    DATA_DIR,
    EMPLOYEE,
    HR,
    PASSWORDS,
    WORKSPACE,
    audit_key,
    fail,
    field,
    line,
    load_state,
    ok,
    paint,
    save_state,
    section,
    short,
    table,
    title,
    verdict_mark,
)

from reservix_crypto import audit_chain, keystore, pki, reservix, signing

SOURCE = DATA_DIR / "Акт_стажировки_Иванов.txt"


def main() -> None:
    title("ШАГ 2. Загрузка и подписание документа личного дела")
    ws = WORKSPACE
    state = load_state()
    root = pki.trusted_root(ws.trust_dir)
    key = audit_key()

    with ws.connect() as conn:
        employee_cert = pki.load(conn, state["certificates"][EMPLOYEE["owner"]])
        hr_cert = pki.load(conn, state["certificates"][HR["owner"]])

        # 1. Загрузка, как это делает Reservix
        section("1. Загрузка в хранилище Reservix (apps/documents/services.py → upload)")
        document = reservix.upload(
            ws,
            conn,
            source=SOURCE,
            title="Акт о прохождении стажировки (ИПР)",
            kind="report",
            employee_id=EMPLOYEE["id"],
            uploaded_by=HR["name"],
        )
        field("Документ", document["title"])
        field("Сотрудник", EMPLOYEE["name"])
        field("Идентификатор", document["public_id"])
        field("Файл на диске", document["file"] + paint("  (обезличенное имя)", "dim"))
        field("Размер", f"{document['size_bytes']} байт")
        field("SHA-256 (как в Reservix)", short(document["checksum"], 24))
        audit_chain.append(
            conn,
            key,
            action="create",
            actor_repr=HR["name"],
            actor_role="hr",
            object_id=document["public_id"],
            object_repr=document["title"],
            message="Документ принят в хранилище",
            ip_address="10.0.12.40",
            request_path="/documents/upload/",
            request_method="POST",
        )
        if reservix.verify_integrity(ws, document):
            ok("verify_integrity: контрольная сумма совпадает")

        # 2. Подпись сотрудника
        section("2. Подпись сотрудника (назначение: author)")
        employee_key = keystore.load(ws.keys_dir, EMPLOYEE["owner"], PASSWORDS[EMPLOYEE["owner"]])
        ok(f"Ключ подписи {EMPLOYEE['name']} расшифрован паролем владельца")
        digest = signing.content_digest(reservix.file_path(ws, document))
        field("Стрибог-256 файла", short(digest, 24))
        sig_id = signing.sign_document(
            ws, conn, document, cert=employee_cert, private_key=employee_key, purpose=signing.PURPOSE_AUTHOR
        )
        row = conn.execute("SELECT * FROM documents_signature WHERE id = ?", (sig_id,)).fetchone()
        payload = signing.signed_attributes(
            document,
            digest=row["content_digest"],
            purpose=row["purpose"],
            signer_serial=row["signer_serial"],
            signed_at=row["signed_at"],
        )
        line(paint("Подписываемые атрибуты (подпись связана не только с файлом, но и с документом):", "dim"))
        for name, value in json.loads(payload).items():
            text = short(str(value), 20) if len(str(value)) > 48 else str(value)
            line(f"    {paint(name.ljust(20), 'cyan')} {text}")
        field("Подпись r", short(row["signature"][:64], 20))
        field("Подпись s", short(row["signature"][64:], 20))
        audit_chain.append(
            conn,
            key,
            action="update",
            actor_repr=EMPLOYEE["name"],
            actor_role="employee",
            object_id=document["public_id"],
            object_repr=document["title"],
            message="Документ подписан сотрудником",
            ip_address="10.0.15.112",
            request_path=f"/documents/{document['public_id']}/sign/",
            request_method="POST",
        )

        # 3. Согласование кадровой службой
        section("3. Согласование кадровой службой (назначение: approval)")
        hr_key = keystore.load(ws.keys_dir, HR["owner"], PASSWORDS[HR["owner"]])
        signing.sign_document(ws, conn, document, cert=hr_cert, private_key=hr_key, purpose=signing.PURPOSE_APPROVAL)
        ok(f"Документ согласован: {HR['name']}")
        audit_chain.append(
            conn,
            key,
            action="approve",
            actor_repr=HR["name"],
            actor_role="hr",
            object_id=document["public_id"],
            object_repr=document["title"],
            message="Документ согласован кадровой службой",
            ip_address="10.0.12.40",
            request_path=f"/documents/{document['public_id']}/approve/",
            request_method="POST",
        )

        # 4. Проверка
        section("4. Проверка подписей")
        verdicts = signing.verify_document(ws, conn, document["public_id"], root)
        table(
            ["№", "Назначение", "Подписант", "Время", "Результат"],
            [
                [str(v.signature_id), signing.PURPOSES[v.purpose], v.signer, v.signed_at, verdict_mark(v.valid)]
                for v in verdicts
            ],
        )

        # 5. Политика
        section("5. Интерфейс не даёт подписать документ за другого")
        try:
            signing.sign_document(ws, conn, document, cert=hr_cert, private_key=hr_key, purpose=signing.PURPOSE_AUTHOR)
            fail("Подпись за сотрудника принята — так быть не должно")
        except PermissionError as error:
            ok(f"{HR['name']} не может поставить подпись сотрудника: {error}")

    state["document"] = document["public_id"]
    save_state(state)
    print()
    line(paint("Готово. Документ загружен, подписан и согласован.", "bold"))


if __name__ == "__main__":
    main()
