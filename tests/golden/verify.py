# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Re-capture the golden master into a temp dir and diff against the frozen
files under tests/golden/. Exit 0 when byte-identical, 1 otherwise."""

from __future__ import annotations

import difflib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capture  # noqa: E402


def main() -> int:
    frozen_dir = capture.GOLDEN_DIR
    with tempfile.TemporaryDirectory() as tmp:
        fresh_dir = Path(tmp)
        fresh = capture.capture()
        for rel, content in fresh.items():
            p = fresh_dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")

        ok = True
        # Every golden file must exist and match byte-for-byte.
        for rel in sorted(fresh):
            fresh_p = fresh_dir / rel
            frozen_p = frozen_dir / rel
            if not frozen_p.exists():
                print(f"MISSING golden file: {rel}")
                ok = False
                continue
            if fresh_p.read_text(encoding="utf-8") != frozen_p.read_text(
                encoding="utf-8"
            ):
                print(f"DRIFT in {rel}:")
                for line in difflib.unified_diff(
                    frozen_p.read_text(encoding="utf-8").splitlines(),
                    fresh_p.read_text(encoding="utf-8").splitlines(),
                    fromfile=f"golden/{rel}",
                    tofile=f"fresh/{rel}",
                    lineterm="",
                ):
                    print("  " + line)
                ok = False
        # Stale golden files (no longer captured) are drift too.
        for frozen_p in sorted(frozen_dir.rglob("*")):
            if (
                frozen_p.is_file()
                and "__pycache__" not in frozen_p.parts
                and frozen_p.name not in {
                    "capture.py", "capture_main.py", "verify.py", "README.md",
                }
            ):
                rel = frozen_p.relative_to(frozen_dir).as_posix()
                if rel not in fresh:
                    print(f"STALE golden file: {rel}")
                    ok = False

    if ok:
        print(
            f"golden master OK — {len(fresh)} outputs byte-identical "
            f"(salt {capture.GOLDEN_SALT!r}, tenant {capture.TENANT!r})"
        )
        return 0
    print("golden master DRIFT — the refactor changed output", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
