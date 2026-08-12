# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The golden-master gate, wired into pytest.

The frozen outputs under tests/golden/ capture the pre-refactor byte stream:
masked responses (free-text on/off), the Option B Python twin, the artifact
builders, the committed artifact set and the token scheme. Any refactor commit
must re-run this and stay byte-identical; a drift here means the refactor
changed output.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "golden"))

import capture  # noqa: E402

# Files under golden/ that are NOT golden outputs (the tooling itself).
_TOOLING = {
    "capture.py",
    "capture_main.py",
    "verify.py",
    "README.md",
}


def test_golden_master_byte_identical() -> None:
    golden_dir = capture.GOLDEN_DIR
    fresh = capture.capture()

    # Every captured output matches its frozen twin byte-for-byte.
    for rel, content in fresh.items():
        frozen = golden_dir / rel
        assert frozen.is_file(), f"missing golden file: {rel}"
        assert (
            frozen.read_text(encoding="utf-8") == content
        ), f"golden drift in {rel}: output changed"

    # No stale golden outputs left behind.
    captured = set(fresh)
    for frozen in golden_dir.rglob("*"):
        if (
            not frozen.is_file()
            or "__pycache__" in frozen.parts
            or frozen.name in _TOOLING
        ):
            continue
        rel = frozen.relative_to(golden_dir).as_posix()
        assert rel in captured, f"stale golden file: {rel}"


def test_golden_capture_is_deterministic() -> None:
    """Two captures in the same process are byte-identical (no hidden state)."""
    first = capture.capture()
    second = capture.capture()
    assert first == second
