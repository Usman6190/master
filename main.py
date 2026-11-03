"""CreativeStall Security & Performance Audit Bot — application entry point."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

if getattr(sys, "frozen", False):
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(Path(sys.executable).parent / "ms-playwright"))


def main() -> int:
    from utils.logging_setup import setup_logging
    setup_logging()
    if "--self-test" in sys.argv:
        from engine.environment import validate
        bad = [c for c in validate(check_browser=False) if c.required and not c.ok]
        for c in bad:
            print(f"FAIL {c.name}: {c.detail}")
        print("SELF-TEST", "OK" if not bad else "FAILED")
        return 1 if bad else 0
    from gui.main_window import run_app
    return run_app()


if __name__ == "__main__":
    sys.exit(main())
