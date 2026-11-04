"""Общие вещи для демо: пути, участники, пароли, вывод в консоль."""

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reservix_crypto.workspace import Workspace  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent / "data"
WORKSPACE = Workspace(ROOT / "workspace")
STATE_FILE = WORKSPACE.root / "state.json"

# Участники

CA_NAME = "Удостоверяющий центр Reservix"

EMPLOYEE = {
    "id": 17,
    "owner": "employee-17",
    "subject_id": "employee:17",
    "name": "Иванов Иван Иванович",
    "role": "Ведущий инженер-технолог, резервист",
}
MANAGER = {"id": 21, "name": "Сидоров Сергей Сергеевич", "role": "Начальник производства"}
HR = {
    "owner": "hr-petrova",
    "subject_id": "hr:petrova",
    "name": "Петрова Анна Андреевна",
    "role": "Специалист кадровой службы",
}
AUDIT = {
    "owner": "system-audit",
    "subject_id": "system:audit",
    "name": "Служба аудита Reservix",
    "role": "Служебная учётная запись",
}

# Пароли демо-ключей. В жизни их вводит пользователь, здесь зашиты, чтобы демо шло без остановок.
PASSWORDS = {
    "ca-root": "Корень-УЦ-2026!",
    "employee-17": "Иванов#Резерв-2026",
    "hr-petrova": "Петрова#Кадры-2026",
    "system-audit": "Аудит#Служба-2026",
}

# Оформление

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if os.name == "nt":
    os.system("")  # включает обработку ANSI-последовательностей в консоли Windows

USE_COLOR = bool(os.environ.get("FORCE_COLOR")) or (sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
WIDTH = 92

_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
}


def paint(text: str, *styles: str) -> str:
    if not USE_COLOR or not styles:
        return text
    codes = ";".join(_CODES[s] for s in styles)
    return f"\x1b[{codes}m{text}\x1b[0m"


def title(text: str) -> None:
    print()
    print(paint("═" * WIDTH, "cyan"))
    print(paint(f"  {text}", "bold", "cyan"))
    print(paint("═" * WIDTH, "cyan"))


def section(text: str) -> None:
    print()
    print(paint(f"── {text} ", "bold", "white") + paint("─" * max(0, WIDTH - len(text) - 4), "dim"))


def line(text: str = "") -> None:
    print(f"  {text}" if text else "")


def field(label: str, value: object, width: int = 26) -> None:
    print(f"  {paint(label.ljust(width), 'dim')} {value}")


def ok(text: str) -> None:
    print("  " + paint("✓ " + text, "green"))


def fail(text: str) -> None:
    print("  " + paint("✗ " + text, "red", "bold"))


def warn(text: str) -> None:
    print("  " + paint("! " + text, "yellow"))


def attacker(text: str) -> None:
    print("  " + paint("[злоумышленник] ", "magenta", "bold") + paint(text, "magenta"))


def short(value: str, size: int = 16) -> str:
    return value if len(value) <= 2 * size else f"{value[:size]}…{value[-8:]}"


def table(headers: list[str], rows: list[list[str]]) -> None:
    import unicodedata

    def width(text: str) -> int:
        return sum(0 if unicodedata.combining(ch) else 1 for ch in _strip(text))

    widths = [max(width(h), *(width(r[i]) for r in rows)) if rows else width(h) for i, h in enumerate(headers)]

    def render(cells: list[str]) -> str:
        return "  " + "  ".join(c + " " * (w - width(c)) for c, w in zip(cells, widths, strict=True))

    print(paint(render(headers), "bold"))
    print("  " + paint("  ".join("─" * w for w in widths), "dim"))
    for row in rows:
        print(render(row))


def _strip(text: str) -> str:
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def verdict_mark(valid: bool, good: str = "ДЕЙСТВИТЕЛЬНА", bad: str = "НЕДЕЙСТВИТЕЛЬНА") -> str:
    return paint(good, "green", "bold") if valid else paint(bad, "red", "bold")


@contextmanager
def timed(label: str):
    started = time.perf_counter()
    yield
    elapsed = time.perf_counter() - started
    print("  " + paint(f"{label}: {elapsed:.2f} с", "dim"))


# Состояние между шагами


def load_state() -> dict:
    if not STATE_FILE.exists():
        print(paint("Сначала выполните предыдущие шаги демонстрации (01_keys.py, 02_sign_document.py).", "red"))
        raise SystemExit(1)
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def audit_key() -> bytes:
    return bytes.fromhex((WORKSPACE.secrets_dir / "audit_hmac.key").read_text(encoding="utf-8").strip())
