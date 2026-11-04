"""Шаг 3: атаки на подписанный документ.

Злоумышленник может писать в базу и в файлы, но не знает чужих
закрытых ключей и не может заменить trust/root.json.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

from _common import (
    CA_NAME,
    EMPLOYEE,
    HR,
    PASSWORDS,
    WORKSPACE,
    attacker,
    fail,
    line,
    load_state,
    ok,
    paint,
    section,
    table,
    title,
    verdict_mark,
    warn,
)

from reservix_crypto import gost, keystore, pki, reservix, signing

ORIGINAL = "программа выполнена частично (68 %)."
FORGED = "программа выполнена в полном объёме."
ORIGINAL_MARK = "Оценка наставника:  3 из 5"
FORGED_MARK = "Оценка наставника:  5 из 5"


def forge_text(text: str) -> str:
    return text.replace(ORIGINAL, FORGED).replace(ORIGINAL_MARK, FORGED_MARK)


def tamper_file(ws, conn, document) -> None:
    """Правит файл и пересчитывает SHA-256 в базе."""
    path = reservix.file_path(ws, document)
    text = path.read_text(encoding="utf-8")
    path.write_text(forge_text(text), encoding="utf-8")
    conn.execute(
        "UPDATE documents_document SET checksum = ?, size_bytes = ? WHERE public_id = ?",
        (reservix.compute_checksum(path), path.stat().st_size, document["public_id"]),
    )


def check_both(ws, conn, public_id, root) -> tuple[bool, list[signing.Verdict]]:
    document = reservix.get(conn, public_id)
    return reservix.verify_integrity(ws, document), signing.verify_document(ws, conn, public_id, root)


def report(integrity: bool, verdicts: list[signing.Verdict]) -> bool:
    """Печатает обе проверки. True, если подпись поймала атаку."""
    if integrity:
        warn("Reservix verify_integrity (SHA-256): целостность «подтверждена» — подмена НЕ обнаружена")
    else:
        ok("Reservix verify_integrity (SHA-256): расхождение обнаружено")
    detected = False
    for v in verdicts:
        line(f"ЭП ГОСТ · {signing.PURPOSES[v.purpose]} · {v.signer}: {verdict_mark(v.valid)}")
        for problem in v.problems:
            line(paint(f"    — {problem}", "red"))
        detected |= not v.valid
    if detected:
        ok("Электронная подпись обнаружила атаку")
    else:
        fail("Атака не обнаружена")
    return detected


def main() -> None:
    title("ШАГ 3. Атаки на подписанный документ")
    ws = WORKSPACE
    state = load_state()
    root = pki.trusted_root(ws.trust_dir)
    public_id = state["document"]

    line("Нарушитель может изменять базу данных и файлы, но не знает чужих закрытых ключей")
    line("и не может изменить закреплённый корневой сертификат (trust/root.json).")
    line(f"Цель: исправить итог стажировки «{ORIGINAL[:-1]}» на «{FORGED[:-1]}»,")
    line("чтобы поднять индекс готовности резервиста к назначению.")
    ws.snapshot()
    summary: list[list[str]] = []

    try:
        # Атака 1
        section("Атака 1. Подмена файла и пересчёт контрольной суммы SHA-256")
        with ws.connect() as conn:
            document = reservix.get(conn, public_id)
            attacker("правит файл на диске: " + FORGED)
            attacker("пересчитывает SHA-256 и обновляет documents_document.checksum")
            tamper_file(ws, conn, document)
            integrity, verdicts = check_both(ws, conn, public_id, root)
        detected = report(integrity, verdicts)
        summary.append(["1. Подмена файла + пересчёт SHA-256", _mark(not integrity), _mark(detected)])
        ws.restore()

        # Атака 2
        section("Атака 2. Переподписание собственным ключом от имени сотрудника")
        with ws.connect() as conn:
            document = reservix.get(conn, public_id)
            tamper_file(ws, conn, document)
            document = reservix.get(conn, public_id)
            attacker("создаёт свою пару ключей ГОСТ Р 34.10-2012")
            fake_key = gost.generate_private_key()
            real_root_serial = state["root_serial"]
            attacker(f"оформляет сертификат на имя «{EMPLOYEE['name']}» от имени «{CA_NAME}»")
            fake_cert = pki.Certificate(
                serial=pki.new_serial(),
                subject_id=EMPLOYEE["subject_id"],
                subject_name=EMPLOYEE["name"],
                subject_role=EMPLOYEE["role"],
                public_key=gost.encode_public_key(gost.public_key(fake_key)).hex(),
                key_usage=(pki.USAGE_DOCUMENTS,),
                valid_from=dt.date.today().isoformat(),
                valid_to=dt.date.today().replace(year=dt.date.today().year + 1).isoformat(),
                issuer_serial=real_root_serial,
                issuer_name=CA_NAME,
            )
            # ключа УЦ у него нет, подписывает своим
            fake_cert = dataclasses.replace(fake_cert, signature=gost.sign(fake_key, fake_cert.to_be_signed()).hex())
            pki.save(conn, fake_cert)
            attacker("удаляет подпись сотрудника и ставит свою на изменённый документ")
            conn.execute(
                "DELETE FROM documents_signature WHERE document_id = ? AND purpose = ?",
                (public_id, signing.PURPOSE_AUTHOR),
            )
            signing.create_signature(
                ws, conn, document, cert=fake_cert, private_key=fake_key, purpose=signing.PURPOSE_AUTHOR
            )
            payload_ok = _math_only(ws, conn, public_id, fake_cert)
            line(
                "Математическая проверка новой подписи ключом из поддельного сертификата: "
                + verdict_mark(payload_ok, "ВЕРНА", "НЕВЕРНА")
            )
            line(paint("…но ключ должен быть удостоверен доверенным УЦ:", "dim"))
            integrity, verdicts = check_both(ws, conn, public_id, root)
        detected = report(integrity, verdicts)
        summary.append(["2. Переподписание своим ключом", _mark(not integrity), _mark(detected)])
        ws.restore()

        # Атака 3
        section("Атака 3. Перенос настоящих подписей на другой документ")
        with ws.connect() as conn:
            original = reservix.get(conn, public_id)
            forged_source = ws.root / "_forged.txt"
            forged_source.write_text(
                forge_text(reservix.file_path(ws, original).read_text(encoding="utf-8")), encoding="utf-8"
            )
            attacker("загружает исправленный акт как новый документ (SHA-256 вычисляется честно)")
            forged = reservix.upload(
                ws,
                conn,
                source=forged_source,
                title=original["title"],
                kind=original["kind"],
                employee_id=original["employee_id"],
                uploaded_by=HR["name"],
            )
            forged_source.unlink()
            new_digest = signing.content_digest(reservix.file_path(ws, forged))
            attacker("копирует обе подписи с настоящего акта и подставляет хеш-код нового файла")
            conn.execute(
                """
                INSERT INTO documents_signature(document_id, purpose, signer_serial, signed_at, content_digest, signature)
                SELECT ?, purpose, signer_serial, signed_at, ?, signature
                FROM documents_signature WHERE document_id = ?
                """,
                (forged["public_id"], new_digest, public_id),
            )
            integrity, verdicts = check_both(ws, conn, forged["public_id"], root)
        detected = report(integrity, verdicts)
        summary.append(["3. Перенос подписей на другой документ", _mark(not integrity), _mark(detected)])
        ws.restore()

        # Атака 4
        section("Атака 4. Сотрудник кадровой службы подписывает за резервиста")
        with ws.connect() as conn:
            document = reservix.get(conn, public_id)
            attacker(f"{HR['name']} (настоящий действующий ключ) правит акт в обход интерфейса")
            tamper_file(ws, conn, document)
            document = reservix.get(conn, public_id)
            conn.execute("DELETE FROM documents_signature WHERE document_id = ?", (public_id,))
            hr_cert = pki.load(conn, state["certificates"][HR["owner"]])
            hr_key = keystore.load(ws.keys_dir, HR["owner"], PASSWORDS[HR["owner"]])
            attacker("ставит подпись сотрудника и согласование своим ключом")
            for purpose in (signing.PURPOSE_AUTHOR, signing.PURPOSE_APPROVAL):
                signing.create_signature(ws, conn, document, cert=hr_cert, private_key=hr_key, purpose=purpose)
            integrity, verdicts = check_both(ws, conn, public_id, root)
        detected = report(integrity, verdicts)
        line(
            paint(
                "Согласование действительно: подпись настоящая и принадлежит кадровой службе. "
                "Но подписи сотрудника под документом больше нет — документ не принимается.",
                "dim",
            )
        )
        summary.append(["4. Подпись за сотрудника чужим ключом", _mark(not integrity), _mark(detected)])
    finally:
        ws.restore()
        ws.drop_snapshot()
        forged_tmp = ws.root / "_forged.txt"
        if forged_tmp.exists():
            forged_tmp.unlink()

    section("Итог")
    table(["Атака", "SHA-256 (Reservix)", "ЭП ГОСТ Р 34.10-2012"], summary)
    with ws.connect() as conn:
        integrity, verdicts = check_both(ws, conn, public_id, root)
    if integrity and all(v.valid for v in verdicts):
        ok("Исходное состояние восстановлено, подписи настоящего документа действительны")


def _mark(detected: bool) -> str:
    return paint("обнаружено", "green", "bold") if detected else paint("не обнаружено", "red", "bold")


def _math_only(ws, conn, public_id: str, cert: pki.Certificate) -> bool:
    """Только уравнение подписи, без проверки сертификата."""
    document = reservix.get(conn, public_id)
    row = conn.execute(
        "SELECT * FROM documents_signature WHERE document_id = ? AND signer_serial = ?", (public_id, cert.serial)
    ).fetchone()
    payload = signing.signed_attributes(
        document,
        digest=signing.content_digest(reservix.file_path(ws, document)),
        purpose=row["purpose"],
        signer_serial=row["signer_serial"],
        signed_at=row["signed_at"],
    )
    return gost.verify(cert.public_key_bytes, payload, bytes.fromhex(row["signature"]))


if __name__ == "__main__":
    main()
