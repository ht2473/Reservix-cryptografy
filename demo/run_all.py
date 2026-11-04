"""Все шаги подряд. С --pause ждёт Enter между шагами."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

STEPS = ["01_keys.py", "02_sign_document.py", "03_attack_document.py", "04_audit_chain.py"]


def main() -> int:
    pause = "--pause" in sys.argv
    here = Path(__file__).resolve().parent
    for index, script in enumerate(STEPS):
        code = subprocess.call([sys.executable, str(here / script)])
        if code != 0:
            print(f"Шаг {script} завершился с кодом {code}")
            return code
        if pause and index < len(STEPS) - 1:
            input("\n  Enter — следующий шаг…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
