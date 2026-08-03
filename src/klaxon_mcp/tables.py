# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Fixed-width table rendering, shared by the tools that summarise rather than
pass through.

Deliberately dumb: it lays out the strings it is given and computes nothing. A
cell that reads '-' was written as '-' by the caller, because a renderer that
decides what an absent measurement looks like is a renderer that can turn one
into a zero.
"""

from __future__ import annotations

from collections.abc import Sequence

EMPTY = "(none)"


def table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    right: Sequence[int] = (),
) -> str:
    """Render `rows` under `headers`. `right` lists the columns to right-align."""
    if not rows:
        return EMPTY

    cells = [[str(cell) for cell in row] for row in rows]
    head = [str(cell) for cell in headers]
    widths = [max(len(row[i]) for row in [head, *cells]) for i in range(len(head))]

    def line(row: Sequence[str]) -> str:
        return "  ".join(
            cell.rjust(widths[i]) if i in right else cell.ljust(widths[i])
            for i, cell in enumerate(row)
        ).rstrip()

    rendered_head = line(head)
    return "\n".join(
        [rendered_head, "-" * len(rendered_head), *(line(row) for row in cells)]
    )
