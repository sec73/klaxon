# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The frozen findings query behind the `findings_overview` tool.

A terms aggregation returns the values it found, and only those. That is the
right behaviour for a search API and the wrong shape for a report: when
`critical` is missing from the response, the buckets alone cannot distinguish
"there were no critical findings" from "this field never carries that value".
Both render as an absent row, and an absent row reads as a zero nobody checked.

So this module does not report buckets. It reports the full severity scale in
canonical order, filling in an explicit 0 for every level the aggregation did
not return — a claim of "no critical findings" that can point at the row it was
read from. A value outside the scale is added and marked unknown rather than
dropped, because the scale is what was measured on one instance, not a
guarantee.

Everything in here is pure: query in, dataclass out, string out. The tool layer
in server.py does the I/O and the exists-probe that decides whether any of this
is worth rendering at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .constants import (
    CATEGORY_TERMS_SIZE,
    FINDINGS_AGENT_NAME_FIELD,
    FINDINGS_CATEGORY_FIELD,
    FINDINGS_LEVEL_FIELD,
    FINDINGS_TITLE_FIELD,
    SEVERITY_SCALE,
    SEVERITY_TERMS_SIZE,
    TIME_FIELD,
)
from .tables import table

# Aggregation names. Shared between the request builder, the parser and the
# diagnostics layer, which maps them back onto field names off the request body.
AGG_SEVERITY = "severity"
AGG_AGENTS = "agents"
AGG_AGENT_COUNT = "agent_count"
AGG_TITLES = "titles"
AGG_TITLE_COUNT = "title_count"
AGG_CATEGORIES = "categories"


# --------------------------------------------------------------------------- #
# Request
# --------------------------------------------------------------------------- #


def _severity_agg() -> dict[str, Any]:
    """A fresh severity sub-aggregation per call site (no shared mutable dict)."""
    return {"terms": {"field": FINDINGS_LEVEL_FIELD, "size": SEVERITY_TERMS_SIZE}}


def time_range(hours: int) -> str:
    return f"now-{hours}h"


def build_query(hours: int, top_agents: int, top_titles: int) -> dict[str, Any]:
    """The whole query, in one place.

    `track_total_hits` is not optional here. Without it OpenSearch stops
    counting at 10000 and reports `"relation": "gte"`, and a findings report
    whose headline number is silently a lower bound is worse than no number.
    """
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {"range": {TIME_FIELD: {"gte": time_range(hours)}}},
        "aggs": {
            AGG_SEVERITY: _severity_agg(),
            AGG_AGENTS: {
                "terms": {"field": FINDINGS_AGENT_NAME_FIELD, "size": top_agents},
                "aggs": {AGG_SEVERITY: _severity_agg()},
            },
            AGG_AGENT_COUNT: {"cardinality": {"field": FINDINGS_AGENT_NAME_FIELD}},
            AGG_TITLES: {"terms": {"field": FINDINGS_TITLE_FIELD, "size": top_titles}},
            AGG_TITLE_COUNT: {"cardinality": {"field": FINDINGS_TITLE_FIELD}},
            AGG_CATEGORIES: {
                "terms": {"field": FINDINGS_CATEGORY_FIELD, "size": CATEGORY_TERMS_SIZE}
            },
        },
    }


# --------------------------------------------------------------------------- #
# Response
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Bucket:
    key: str
    count: int


@dataclass(frozen=True)
class SeverityRow:
    level: str
    count: int
    known: bool


@dataclass
class Overview:
    """The parsed response. Absent aggregations become empty, never invented."""

    total: int = 0
    total_is_lower_bound: bool = False
    severity: dict[str, int] = field(default_factory=dict)
    severity_other: int = 0
    agents: list[Bucket] = field(default_factory=list)
    agents_other: int = 0
    agent_cardinality: int | None = None
    # agent name -> {level: count}
    agent_severity: dict[str, dict[str, int]] = field(default_factory=dict)
    titles: list[Bucket] = field(default_factory=list)
    titles_other: int = 0
    title_cardinality: int | None = None
    categories: list[Bucket] = field(default_factory=list)
    categories_other: int = 0


def _buckets(node: Any) -> list[Bucket]:
    if not isinstance(node, dict):
        return []
    raw = node.get("buckets")
    if not isinstance(raw, list):
        return []
    out: list[Bucket] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        count = item.get("doc_count")
        if not isinstance(count, int):
            continue
        out.append(Bucket(str(item.get("key")), count))
    return out


def _other(node: Any) -> int:
    if not isinstance(node, dict):
        return 0
    value = node.get("sum_other_doc_count")
    return value if isinstance(value, int) else 0


def _cardinality(node: Any) -> int | None:
    if not isinstance(node, dict):
        return None
    value = node.get("value")
    return value if isinstance(value, int) else None


def parse(payload: Any) -> Overview:
    """Read the aggregation response into an Overview, tolerating any shape."""
    result = Overview()
    if not isinstance(payload, dict):
        return result

    hits = payload.get("hits")
    if isinstance(hits, dict):
        total = hits.get("total")
        if isinstance(total, int):
            result.total = total
        elif isinstance(total, dict):
            value = total.get("value")
            if isinstance(value, int):
                result.total = value
            result.total_is_lower_bound = total.get("relation") == "gte"

    aggs = payload.get("aggregations")
    if not isinstance(aggs, dict):
        return result

    severity_node = aggs.get(AGG_SEVERITY)
    result.severity = {b.key: b.count for b in _buckets(severity_node)}
    result.severity_other = _other(severity_node)

    agents_node = aggs.get(AGG_AGENTS)
    result.agents = _buckets(agents_node)
    result.agents_other = _other(agents_node)
    result.agent_cardinality = _cardinality(aggs.get(AGG_AGENT_COUNT))
    if isinstance(agents_node, dict):
        raw_agents = agents_node.get("buckets")
        if isinstance(raw_agents, list):
            for item in raw_agents:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("key"))
                result.agent_severity[name] = {
                    b.key: b.count for b in _buckets(item.get(AGG_SEVERITY))
                }

    titles_node = aggs.get(AGG_TITLES)
    result.titles = _buckets(titles_node)
    result.titles_other = _other(titles_node)
    result.title_cardinality = _cardinality(aggs.get(AGG_TITLE_COUNT))

    categories_node = aggs.get(AGG_CATEGORIES)
    result.categories = _buckets(categories_node)
    result.categories_other = _other(categories_node)

    return result


# --------------------------------------------------------------------------- #
# The severity scale
# --------------------------------------------------------------------------- #


def unknown_levels(counts: Mapping[str, int]) -> list[str]:
    """Observed values that are not in the documented scale, worst count first.

    No case folding. A `Medium` bucket is not silently merged into `medium`:
    merging it would hide a mapping or decoder change behind a number that still
    looks plausible, which is the failure mode this whole server is built
    against. It surfaces as unknown, and the notice points at the near-match.
    """
    extra = [(key, count) for key, count in counts.items() if key not in SEVERITY_SCALE]
    extra.sort(key=lambda item: (-item[1], item[0]))
    return [key for key, _ in extra]


def severity_rows(counts: Mapping[str, int]) -> list[SeverityRow]:
    """The full scale in canonical order, then anything unexpected, marked.

    The one function this tool exists for. Every level in SEVERITY_SCALE gets a
    row whether or not the aggregation returned a bucket for it, so a zero is a
    measured zero rather than a missing line.
    """
    rows = [
        SeverityRow(level, int(counts.get(level, 0)), True) for level in SEVERITY_SCALE
    ]
    rows.extend(
        SeverityRow(level, int(counts[level]), False) for level in unknown_levels(counts)
    )
    return rows


def severity_columns(counts: Mapping[str, int]) -> list[str]:
    """Cross-tab columns: the whole scale, plus any unknown value observed."""
    return [*SEVERITY_SCALE, *unknown_levels(counts)]


def cross_tab_levels(result: Overview) -> list[str]:
    """Columns for the cross-tab, taken from the nested buckets as well.

    The nested aggregation is computed per agent bucket and can in principle
    surface a value the top-level one truncated away. Reading the columns off
    the top-level agg alone would drop such a value from the table without
    saying anything.
    """
    combined = dict(result.severity)
    for per_level in result.agent_severity.values():
        for level, count in per_level.items():
            combined[level] = combined.get(level, 0) + count
    return severity_columns(combined)


# --------------------------------------------------------------------------- #
# Diagnostics
# --------------------------------------------------------------------------- #

SCALE_NOTICE = (
    "[FULL SCALE SHOWN] The severity table lists every level in the documented "
    f"Wazuh 5 scale ({', '.join(SEVERITY_SCALE)}), including the ones the "
    "aggregation returned no bucket for. A row reading 0 was queried and found "
    "absent in this window — it is a measured zero, not an omitted line. A terms "
    "aggregation on its own cannot support that statement, which is why this "
    "tool exists."
)


def overview_notices(result: Overview, hours: int) -> list[str]:
    """Notices about the overview itself, on top of the generic search notices."""
    notices: list[str] = []

    unknown = unknown_levels(result.severity)
    if unknown:
        near = [
            f"{value!r} (differs only in case from {known!r})"
            for value in unknown
            for known in SEVERITY_SCALE
            if value.casefold() == known.casefold()
        ]
        hint = (
            f" Case mismatch: {'; '.join(near)}. Values are compared exactly, so "
            f"this is reported rather than folded into the known level."
            if near
            else ""
        )
        notices.append(
            f"[UNKNOWN SEVERITY VALUE] {FINDINGS_LEVEL_FIELD} holds "
            f"{len(unknown)} value(s) outside the documented scale: "
            f"{', '.join(repr(u) for u in unknown)}. They are listed in the table "
            f"below and marked UNKNOWN. The scale was measured on one instance and "
            f"is not authoritative — treat these as real findings, not as noise."
            f"{hint}"
        )

    if result.severity_other:
        notices.append(
            f"[SEVERITY SCALE TRUNCATED] The severity aggregation reports "
            f"sum_other_doc_count={result.severity_other}, so "
            f"{FINDINGS_LEVEL_FIELD} holds more than {SEVERITY_TERMS_SIZE} distinct "
            f"values and some of them are not in the table below. That many levels "
            f"means the field is not the severity scale it is read as here — check "
            f"it with `search` before using these counts."
        )

    if result.agent_cardinality is not None and result.agent_cardinality > len(
        result.agents
    ):
        notices.append(
            f"[AGENT LIST TRUNCATED] {result.agent_cardinality} distinct agents "
            f"produced findings in the last {hours}h; the table shows the top "
            f"{len(result.agents)} by count. The remaining agents account for "
            f"{result.agents_other} finding(s) (sum_other_doc_count). Raise "
            f"`top_agents` to see them."
        )

    if result.title_cardinality is not None and result.title_cardinality > len(
        result.titles
    ):
        notices.append(
            f"[TITLE LIST TRUNCATED] {result.title_cardinality} distinct rule titles "
            f"occurred in the last {hours}h; the table shows the top "
            f"{len(result.titles)}. The remaining titles account for "
            f"{result.titles_other} finding(s). Raise `top_titles` to see them."
        )

    if result.categories_other:
        notices.append(
            f"[CATEGORY LIST TRUNCATED] {result.categories_other} finding(s) fall "
            f"outside the {len(result.categories)} categories listed. Wazuh 5 defines "
            f"eight fixed categories, so this should not happen — check "
            f"{FINDINGS_CATEGORY_FIELD} in the index."
        )

    return notices


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _pct(count: int, total: int) -> str:
    if total <= 0:
        return "-"
    return f"{(count / total) * 100:.1f}%"


def _render_severity(result: Overview) -> str:
    rows = [
        [
            row.level,
            str(row.count),
            _pct(row.count, result.total),
            "" if row.known else "UNKNOWN — not in the documented scale",
        ]
        for row in severity_rows(result.severity)
    ]
    return table(["LEVEL", "COUNT", "PCT", ""], rows, right=(1, 2))


def _render_agents(result: Overview) -> str:
    rows = [
        [b.key, str(b.count), _pct(b.count, result.total)] for b in result.agents
    ]
    return table(["AGENT", "COUNT", "PCT"], rows, right=(1, 2))


def _render_cross_tab(result: Overview) -> str:
    columns = cross_tab_levels(result)
    rows = []
    for bucket in result.agents:
        per_level = result.agent_severity.get(bucket.key, {})
        rows.append(
            [
                bucket.key,
                *(str(per_level.get(level, 0)) for level in columns),
                str(bucket.count),
            ]
        )
    headers = ["AGENT", *columns, "TOTAL"]
    return table(headers, rows, right=tuple(range(1, len(headers))))


def _render_titles(result: Overview) -> str:
    rows = [[str(b.count), _pct(b.count, result.total), b.key] for b in result.titles]
    return table(["COUNT", "PCT", "TITLE"], rows, right=(0, 1))


def _render_categories(result: Overview) -> str:
    rows = [
        [b.key, str(b.count), _pct(b.count, result.total)] for b in result.categories
    ]
    return table(["CATEGORY", "COUNT", "PCT"], rows, right=(1, 2))


def _section(title: str, body: str) -> str:
    return f"{title}\n{body}"


def _scope(shown: int, total: int | None) -> str:
    """Label a truncated list by what came back, never by what was requested.

    `top 10 of 5` is the shape of a caption that quietly overstates its table.
    The count of rows below is the only number that cannot be wrong.
    """
    if total is None:
        return f"top {shown}"
    return f"top {shown} of {total}"


def render(result: Overview) -> str:
    """The whole report, compact. The caller gets tables, not JSON."""
    agent_scope = _scope(len(result.agents), result.agent_cardinality)
    title_scope = _scope(len(result.titles), result.title_cardinality)

    sections = [
        _section(f"SEVERITY  ({FINDINGS_LEVEL_FIELD})", _render_severity(result)),
        _section(
            f"AGENTS  ({FINDINGS_AGENT_NAME_FIELD}, {agent_scope})",
            _render_agents(result),
        ),
        _section("CROSS-TAB  agent x severity", _render_cross_tab(result)),
        _section(
            f"TOP TITLES  ({FINDINGS_TITLE_FIELD}, {title_scope})",
            _render_titles(result),
        ),
        _section(
            f"CATEGORIES  ({FINDINGS_CATEGORY_FIELD})", _render_categories(result)
        ),
    ]
    return "\n\n".join(sections)


def header(
    index: str, hours: int, total: int | None, level_doc_count: int | None
) -> str:
    """The block above the tables: what was asked, and of what.

    `total=None` means the query was never sent. Printing 0 there would put a
    number nobody measured beside numbers that were measured — the same
    fabrication as a bucket that quietly never existed.
    """
    lines = [
        f"index:          {index}",
        f"window:         last {hours}h ({TIME_FIELD} >= {time_range(hours)})",
        f"findings:       {'(not queried)' if total is None else total}",
    ]
    if level_doc_count is not None:
        lines.append(
            f"severity field: {FINDINGS_LEVEL_FIELD} "
            f"(populated in {level_doc_count} document(s) index-wide)"
        )
    return "\n".join(lines)
