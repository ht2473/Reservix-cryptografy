"""Те же атаки, что в демо, но в виде тестов."""

from __future__ import annotations

import datetime as dt

import pytest

from reservix_crypto import audit_chain, gost, pki, reservix, signing
from reservix_crypto.workspace import Workspace

TODAY = dt.date.today()


@pytest.fixture
def env(tmp_path):
    ws = Workspace(tmp_path / "ws")
    ws.create()
    root, root_key = pki.create_root("УЦ", TODAY)
    pki.pin_root(ws.trust_dir, root)

    def make(subject_id, usage):
        d = gost.generate_private_key()
        cert = pki.issue(
            root,
            root_key,
            subject_id=subject_id,
            subject_name=subject_id,
            subject_role="",
            public_key=gost.public_key(d),
            key_usage=usage,
            valid_from=TODAY,
        )
        return cert, d

    employee = make("employee:17", (pki.USAGE_DOCUMENTS,))
    hr = make("hr:petrova", (pki.USAGE_DOCUMENTS,))
    audit = make("system:audit", (pki.USAGE_AUDIT,))

    source = tmp_path / "act.txt"
    source.write_text("Итог стажировки: программа выполнена частично (68 %).", encoding="utf-8")
    with ws.connect() as conn:
        conn.execute("INSERT INTO people_employee VALUES (17, 'Иванов', 'инженер')")
        for cert, _ in (employee, hr, audit):
            pki.save(conn, cert)
        doc = reservix.upload(ws, conn, source=source, title="Акт", kind="report", employee_id=17, uploaded_by="hr")
        signing.sign_document(ws, conn, doc, cert=employee[0], private_key=employee[1], purpose=signing.PURPOSE_AUTHOR)
        signing.sign_document(ws, conn, doc, cert=hr[0], private_key=hr[1], purpose=signing.PURPOSE_APPROVAL)
    return {"ws": ws, "root": root, "doc": doc["public_id"], "employee": employee, "hr": hr, "audit": audit}


def _verdicts(env, public_id=None):
    with env["ws"].connect() as conn:
        return signing.verify_document(env["ws"], conn, public_id or env["doc"], env["root"])


def _tamper(env):
    ws = env["ws"]
    with ws.connect() as conn:
        doc = reservix.get(conn, env["doc"])
        path = reservix.file_path(ws, doc)
        path.write_text("Итог стажировки: программа выполнена в полном объёме.", encoding="utf-8")
        conn.execute(
            "UPDATE documents_document SET checksum = ?, size_bytes = ? WHERE public_id = ?",
            (reservix.compute_checksum(path), path.stat().st_size, env["doc"]),
        )


# Документы


def test_genuine_document_valid(env):
    verdicts = _verdicts(env)
    assert len(verdicts) == 2
    assert all(v.valid for v in verdicts)


def test_sha256_misses_tampering_but_signature_catches_it(env):
    _tamper(env)
    with env["ws"].connect() as conn:
        assert reservix.verify_integrity(env["ws"], reservix.get(conn, env["doc"]))  # слабость исходной схемы
    assert not any(v.valid for v in _verdicts(env))


def test_resigning_with_selfmade_certificate_rejected(env):
    import dataclasses

    _tamper(env)
    ws = env["ws"]
    fake_key = gost.generate_private_key()
    genuine = env["employee"][0]
    fake = dataclasses.replace(
        genuine,
        serial=pki.new_serial(),
        public_key=gost.encode_public_key(gost.public_key(fake_key)).hex(),
    )
    fake = dataclasses.replace(fake, signature=gost.sign(fake_key, fake.to_be_signed()).hex())
    with ws.connect() as conn:
        pki.save(conn, fake)
        conn.execute("DELETE FROM documents_signature")
        doc = reservix.get(conn, env["doc"])
        signing.create_signature(ws, conn, doc, cert=fake, private_key=fake_key, purpose=signing.PURPOSE_AUTHOR)
    (verdict,) = _verdicts(env)
    assert not verdict.valid
    assert "подпись удостоверяющего центра под сертификатом неверна" in verdict.problems


def test_signature_cannot_be_moved_to_other_document(env, tmp_path):
    ws = env["ws"]
    other_source = tmp_path / "other.txt"
    other_source.write_text("Другой документ", encoding="utf-8")
    with ws.connect() as conn:
        other = reservix.upload(ws, conn, source=other_source, title="Акт", kind="report", employee_id=17, uploaded_by="x")
        digest = signing.content_digest(reservix.file_path(ws, other))
        conn.execute(
            """INSERT INTO documents_signature(document_id, purpose, signer_serial, signed_at, content_digest, signature)
               SELECT ?, purpose, signer_serial, signed_at, ?, signature FROM documents_signature WHERE document_id = ?""",
            (other["public_id"], digest, env["doc"]),
        )
    verdicts = _verdicts(env, other["public_id"])
    assert verdicts and not any(v.valid for v in verdicts)


def test_metadata_change_breaks_signature(env):
    with env["ws"].connect() as conn:
        conn.execute("UPDATE documents_document SET employee_id = 21 WHERE public_id = ?", (env["doc"],))
    assert not any(v.valid for v in _verdicts(env))


def test_policy_rejects_hr_signing_as_author(env):
    ws = env["ws"]
    cert, key = env["hr"]
    with ws.connect() as conn:
        doc = reservix.get(conn, env["doc"])
        with pytest.raises(PermissionError):
            signing.sign_document(ws, conn, doc, cert=cert, private_key=key, purpose=signing.PURPOSE_AUTHOR)
        conn.execute("DELETE FROM documents_signature WHERE purpose = 'author'")
        signing.create_signature(ws, conn, doc, cert=cert, private_key=key, purpose=signing.PURPOSE_AUTHOR)
    author = [v for v in _verdicts(env) if v.purpose == signing.PURPOSE_AUTHOR]
    assert author and not author[0].valid


def test_missing_file_reported(env):
    ws = env["ws"]
    with ws.connect() as conn:
        reservix.file_path(ws, reservix.get(conn, env["doc"])).unlink()
    assert all("файл документа недоступен" in v.problems for v in _verdicts(env))


# Журнал аудита

KEY = bytes(range(32))


@pytest.fixture
def journal(env):
    ws = env["ws"]
    with ws.connect() as conn:
        for number in range(1, 9):
            audit_chain.append(conn, KEY, action="export" if number == 5 else "view", message=f"событие {number}")
        cert, key = env["audit"]
        checkpoint = audit_chain.make_checkpoint(conn, cert, key)
    return ws, checkpoint, env["root"]


def _chain(ws, key=KEY):
    with ws.connect() as conn:
        return audit_chain.verify(conn, key)


def _checkpoint(ws, checkpoint, root):
    with ws.connect() as conn:
        return audit_chain.verify_checkpoint(conn, checkpoint, root)


def test_intact_journal(journal):
    ws, checkpoint, root = journal
    assert _chain(ws).ok and _chain(ws).checked == 8
    assert _checkpoint(ws, checkpoint, root) == []


def test_elevated_severity(journal):
    ws, _, _ = journal
    with ws.connect() as conn:
        assert conn.execute("SELECT severity FROM audit_auditlog WHERE id = 5").fetchone()[0] == "notice"


def test_modified_record_detected(journal):
    ws, _, _ = journal
    with ws.connect() as conn:
        conn.execute("UPDATE audit_auditlog SET message = 'ничего не было' WHERE id = 5")
    report = _chain(ws)
    assert [issue.record_id for issue in report.issues] == [5]


def test_deleted_record_detected(journal):
    ws, _, _ = journal
    with ws.connect() as conn:
        conn.execute("DELETE FROM audit_auditlog WHERE id = 5")
    assert {issue.record_id for issue in _chain(ws).issues} == {6}


def test_swapped_records_detected(journal):
    ws, _, _ = journal
    with ws.connect() as conn:
        a = dict(conn.execute("SELECT * FROM audit_auditlog WHERE id = 3").fetchone())
        b = dict(conn.execute("SELECT * FROM audit_auditlog WHERE id = 4").fetchone())
        for target, source in ((3, b), (4, a)):
            conn.execute(
                "UPDATE audit_auditlog SET message = ?, prev_hash = ?, chain_hash = ? WHERE id = ?",
                (source["message"], source["prev_hash"], source["chain_hash"], target),
            )
    assert not _chain(ws).ok


def test_inserted_forged_record_detected(journal):
    ws, _, _ = journal
    with ws.connect() as conn:
        audit_chain.append(conn, gost.random_bytes(32), action="view", message="поддельная запись")
    report = _chain(ws)
    assert [issue.record_id for issue in report.issues] == [9]


def test_plain_hash_chain_can_be_rebuilt_hmac_cannot(journal):
    ws, checkpoint, root = journal
    with ws.connect() as conn:
        conn.execute("DELETE FROM audit_auditlog WHERE id = 5")
        conn.execute("UPDATE audit_auditlog SET id = id - 1 WHERE id > 5")
        audit_chain.rebuild(conn, None)
    assert _chain(ws, key=None).ok  # простой хеш: подделку не видно
    with ws.connect() as conn:
        audit_chain.rebuild(conn, gost.random_bytes(32))
    assert len(_chain(ws).issues) == 7  # HMAC: неверно каждое звено
    assert _checkpoint(ws, checkpoint, root)


def test_tail_truncation_needs_checkpoint(journal):
    ws, checkpoint, root = journal
    with ws.connect() as conn:
        conn.execute("DELETE FROM audit_auditlog WHERE id >= 6")
    assert _chain(ws).ok  # сама цепочка усечение не видит
    problems = _checkpoint(ws, checkpoint, root)
    assert any("журнал усечён" in p for p in problems)


def test_forged_checkpoint_rejected(journal):
    ws, checkpoint, root = journal
    forged = {**checkpoint, "record_count": 5, "last_id": 5}
    assert "подпись контрольной точки неверна" in _checkpoint(ws, forged, root)
