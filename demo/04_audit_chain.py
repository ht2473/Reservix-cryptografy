"""Шаг 4: журнал аудита, контрольная точка и атаки на журнал."""

from __future__ import annotations

from _common import (
    AUDIT,
    HR,
    MANAGER,
    PASSWORDS,
    WORKSPACE,
    attacker,
    audit_key,
    fail,
    field,
    line,
    load_state,
    ok,
    paint,
    section,
    short,
    table,
    title,
    warn,
)

from reservix_crypto import audit_chain, gost, keystore, pki

ACTION_NAMES = {
    "create": "Создание",
    "update": "Изменение",
    "approve": "Согласование",
    "login": "Вход в систему",
    "view": "Просмотр ПДн",
    "status": "Изменение статуса",
    "export": "Выгрузка данных",
    "login_failed": "Неудачный вход",
    "settings": "Изменение настроек",
}

EVENTS = [
    dict(action="login", actor_repr=MANAGER["name"], actor_role="manager", message="Вход в систему",
         ip_address="10.0.14.7", request_path="/accounts/login/", request_method="POST"),
    dict(action="view", actor_repr=MANAGER["name"], actor_role="manager", object_id="17",
         object_repr="Иванов Иван Иванович", message="Просмотр карточки сотрудника",
         ip_address="10.0.14.7", request_path="/people/17/", request_method="GET"),
    dict(action="export", actor_repr=MANAGER["name"], actor_role="manager", object_repr="Отчёт «Кадровый резерв»",
         message="Выгрузка отчёта «Кадровый резерв» (.xlsx): 148 сотрудников, персональные данные",
         ip_address="10.0.14.7", request_path="/reports/reserve/export/", request_method="GET"),
    dict(action="login_failed", actor_repr="admin", message="Неверный пароль",
         ip_address="185.220.101.33", request_path="/accounts/login/", request_method="POST"),
    dict(action="status", actor_repr=HR["name"], actor_role="hr", object_id="RSV-0042",
         object_repr="Иванов И. И. → начальник цеха", message="Статус записи резерва: «На пересмотре»",
         changes={"status": {"old": "active", "new": "review"}},
         ip_address="10.0.12.40", request_path="/reserve/42/status/", request_method="POST"),
    dict(action="settings", actor_repr="Администратор", actor_role="admin", object_repr="Модель скоринга",
         message="Изменены веса индекса готовности",
         changes={"weight_assessment": {"old": 0.30, "new": 0.15}, "weight_tenure": {"old": 0.10, "new": 0.25}},
         ip_address="10.0.10.2", request_path="/administration/scoring/", request_method="POST"),
]


def print_log(conn) -> None:
    rows = conn.execute("SELECT * FROM audit_auditlog ORDER BY id").fetchall()
    table(
        ["№", "Время", "Пользователь", "Действие", "prev_hash", "chain_hash"],
        [
            [
                str(r["id"]),
                r["created_at"][11:],
                r["actor_repr"][:24],
                ACTION_NAMES.get(r["action"], r["action"]),
                r["prev_hash"][:10] + "…",
                r["chain_hash"][:10] + "…",
            ]
            for r in rows
        ],
    )


def report_chain(result: audit_chain.ChainReport, label: str) -> bool:
    if result.ok:
        return False
    fail(f"{label}: нарушений — {len(result.issues)} (проверено записей: {result.checked})")
    for issue in result.issues[:6]:
        line(paint(f"    запись №{issue.record_id}: {issue.text}", "red"))
    if len(result.issues) > 6:
        line(paint(f"    … и ещё {len(result.issues) - 6}", "red"))
    return True


def report_checkpoint(problems: list[str]) -> bool:
    if not problems:
        return False
    fail("Сверка с контрольной точкой: расхождение")
    for problem in problems:
        line(paint(f"    {problem}", "red"))
    return True


def main() -> None:
    title("ШАГ 4. Журнал аудита: цепочка HMAC-Стрибог-256")
    ws = WORKSPACE
    state = load_state()
    root = pki.trusted_root(ws.trust_dir)
    key = audit_key()

    with ws.connect() as conn:
        # 1. Журнал
        section("1. Работа пользователей: каждая запись сцеплена с предыдущей")
        line(paint("chain_hash(n) = HMAC-Стрибог-256(K, chain_hash(n−1) ‖ запись n),  K — вне базы данных", "dim"))
        for event in EVENTS:
            audit_chain.append(conn, key, **event)
        print_log(conn)

        # 2. Контрольная точка
        section("2. Контрольная точка, подписанная службой аудита")
        audit_cert = pki.load(conn, state["certificates"][AUDIT["owner"]])
        audit_private = keystore.load(ws.keys_dir, AUDIT["owner"], PASSWORDS[AUDIT["owner"]])
        checkpoint = audit_chain.make_checkpoint(conn, audit_cert, audit_private)
        path = audit_chain.export_checkpoint(ws.checkpoints_dir, checkpoint)
        for name, value in checkpoint.items():
            field(name, short(str(value), 20) if len(str(value)) > 48 else value, 14)
        ok(f"Сохранена вне базы данных: {path.relative_to(ws.root.parent)}")

        # 3. Проверка
        section("3. Проверка журнала")
        result = audit_chain.verify(conn, key)
        problems = audit_chain.verify_checkpoint(conn, checkpoint, root)
        if result.ok and not problems:
            ok(f"Цепочка цела: проверено записей — {result.checked}; контрольная точка совпадает")

    export_id = _id_of(ws, "export")
    settings_id = _id_of(ws, "settings")
    ws.snapshot()
    summary: list[list[str]] = []
    try:
        # Атака 1
        section("Атака 1. Исправление записи запросом к базе в обход приложения")
        line(paint("В Reservix AuditLog.save() запрещает изменение («Записи журнала аудита неизменяемы»),", "dim"))
        line(paint("но этот запрет действует только внутри приложения.", "dim"))
        with ws.connect() as conn:
            attacker(f"UPDATE audit_auditlog: запись №{settings_id} об изменении весов индекса готовности")
            attacker("превращается в «Просмотр настроек скоринга», изменения весов стираются")
            conn.execute(
                "UPDATE audit_auditlog SET action = 'view', severity = 'info', "
                "message = 'Просмотр настроек скоринга', changes = '{}', request_method = 'GET' WHERE id = ?",
                (settings_id,),
            )
            detected = report_chain(audit_chain.verify(conn, key), "Проверка цепочки")
        summary.append(["1. Изменение записи", _mark(detected)])
        ws.restore()

        # Атака 2
        section("Атака 2. Удаление записи о выгрузке персональных данных")
        with ws.connect() as conn:
            attacker(f"{MANAGER['name']}: DELETE FROM audit_auditlog WHERE id = {export_id}")
            conn.execute("DELETE FROM audit_auditlog WHERE id = ?", (export_id,))
            detected = report_chain(audit_chain.verify(conn, key), "Проверка цепочки")
        summary.append(["2. Удаление записи", _mark(detected)])
        ws.restore()

        # Атака 3
        section("Атака 3. Удаление записи и пересчёт всей цепочки заново")
        with ws.connect() as conn:
            attacker(f"удаляет запись №{export_id}, перенумеровывает остальные и пересчитывает все звенья")
            conn.execute("DELETE FROM audit_auditlog WHERE id = ?", (export_id,))
            conn.execute("UPDATE audit_auditlog SET id = id - 1 WHERE id > ?", (export_id,))
            line(paint("а) если бы звено было простым хешем Стрибог-256 без ключа:", "bold"))
            audit_chain.rebuild(conn, None)
            plain = audit_chain.verify(conn, None)
            if plain.ok:
                warn(f"проверка простой цепочки: «цела» ({plain.checked} записей) — подделка НЕ обнаружена")
            line(paint("б) звено — HMAC с секретным ключом; нарушитель ключа не знает и подбирает свой:", "bold"))
            audit_chain.rebuild(conn, gost.random_bytes(32))
            detected = report_chain(audit_chain.verify(conn, key), "Проверка цепочки")
            detected |= report_checkpoint(audit_chain.verify_checkpoint(conn, checkpoint, root))
        summary.append(["3. Удаление + пересчёт цепочки", _mark(detected)])
        ws.restore()

        # Атака 4
        section("Атака 4. Удаление последних записей журнала")
        with ws.connect() as conn:
            attacker(f"удаляет записи начиная с №{export_id} — хвост журнала")
            conn.execute("DELETE FROM audit_auditlog WHERE id >= ?", (export_id,))
            chain = audit_chain.verify(conn, key)
            if chain.ok:
                warn(f"сама цепочка «цела» ({chain.checked} записей): остаток журнала — корректная цепочка")
            detected = report_checkpoint(audit_chain.verify_checkpoint(conn, checkpoint, root))
        summary.append(["4. Усечение хвоста журнала", _mark(detected)])
    finally:
        ws.restore()
        ws.drop_snapshot()

    section("Итог")
    table(["Атака", "Цепочка HMAC + контрольная точка"], summary)
    line(paint("Без цепочки (исходный Reservix) ни одна из этих правок не оставляет следа в базе данных.", "dim"))
    with ws.connect() as conn:
        if audit_chain.verify(conn, key).ok and not audit_chain.verify_checkpoint(conn, checkpoint, root):
            ok("Исходный журнал восстановлен, цепочка и контрольная точка сходятся")


def _id_of(ws, action: str) -> int:
    with ws.connect() as conn:
        return conn.execute("SELECT id FROM audit_auditlog WHERE action = ? ORDER BY id DESC", (action,)).fetchone()[0]


def _mark(detected: bool) -> str:
    return paint("обнаружено", "green", "bold") if detected else paint("не обнаружено", "red", "bold")


if __name__ == "__main__":
    main()
