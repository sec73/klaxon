# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Pure logic behind the `parsing_cemetery` tool.

Wazuh 5 has no archives/alerts split: every decoded event lands in
wazuh-events-v5-* and detection output is a separate wazuh-findings-v5-* stream.
"Parsing gaps" are therefore measured on the events stream:

  decoder_gap   — events whose raw line reached the index but was never mapped
                  to an integration dataset (no `event.dataset`). The engine
                  assigns event.dataset only when a specific decoder mapped the
                  source, so "missing event.dataset" is the schema-churn-proof
                  proxy for "matched only a generic decoder" (see the
                  decoder-chain TODO in constants.py for the upgrade path).
  detection_gap — an (agent, category) that produced events in the window but
                  no findings in wazuh-findings-v5-* for the same window and
                  group key: normalised, but nothing was detected from it.

Everything in here is pure: query bodies in, parsed leaves out, report strings
out. The tool layer in server.py does the I/O, decides what to run from the
`classification` argument, and routes samples and agent-name keys through the
anonymization layer before anything is rendered.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Final

from .constants import (
    CLASSIFICATION_DECODER_GAP,
    EVENTS_AGENT_NAME_FIELD,
    EVENTS_CATEGORY_FIELD,
    EVENTS_DATASET_FIELD,
    EVENTS_PATTERN,
    FINDINGS_PATTERN,
    TIME_FIELD,
)
from .tables import table

# --------------------------------------------------------------------------- #
# Bounds and labels
# --------------------------------------------------------------------------- #

# Internal cap on how many agents the counts pass walks. This is not the report
# width (that is `top_n`): it bounds the size of the priority-queue aggregation.
# A deployment with more agents than this gets an explicit notice, never a
# silent top-N-of-an-unknown-total.
AGENT_TERMS_SIZE: Final[int] = 200

# The eight categories are a fixed set (constants.CATEGORIES); the extra room
# keeps an unexpected value out of sum_other_doc_count.
CATEGORY_TERMS_SIZE: Final[int] = 25

# Per-group facet of which concrete sources compose a coarse category.
DATASET_FACET_SIZE: Final[int] = 5

# Parameter ceilings. top_n bounds the returned groups, sample_size bounds the
# nested top_hits documents (and therefore the masking work).
TOP_N_MAX: Final[int] = 200
SAMPLE_SIZE_MAX: Final[int] = 10

# A group is "sustained" when at least this share of the window's histogram
# buckets holds events — the line between a one-off spike and a steady stream.
SUSTAINED_FRACTION: Final[float] = 0.5

MISSING = "-"

# Date-histogram resolution, chosen so a window never asks for an absurd number
# of buckets: 1h up to two days, 6h up to two weeks, 1d beyond.
_HISTOGRAM_STEPS: Final[tuple[tuple[int, str, int], ...]] = (
    (48, "1h", 1),
    (336, "6h", 6),
    (1 << 30, "1d", 24),
)


def histogram_interval(hours: int) -> str:
    """The fixed_interval that keeps a window at a sane bucket count."""
    for ceiling, interval, _ in _HISTOGRAM_STEPS:
        if hours <= ceiling:
            return interval
    return "1d"


def _interval_hours(interval: str) -> int:
    for _, candidate, span in _HISTOGRAM_STEPS:
        if candidate == interval:
            return span
    return 24


def expected_buckets(hours: int) -> int:
    """The number of histogram buckets a full window spans (for SUSTAINED)."""
    interval = histogram_interval(hours)
    span = _interval_hours(interval)
    return max(1, -(-hours // span))


def time_window(hours: int) -> dict[str, Any]:
    """The window as a range query on the one v5 time field."""
    return {"range": {TIME_FIELD: {"gte": f"now-{hours}h"}}}


def no_dataset_filter() -> dict[str, Any]:
    """The decoder_gap scope: events the engine never mapped to a dataset."""
    return {
        "bool": {
            "must_not": [{"exists": {"field": EVENTS_DATASET_FIELD}}],
        }
    }


def _date_histogram(hours: int) -> dict[str, Any]:
    return {
        "date_histogram": {
            "field": TIME_FIELD,
            "fixed_interval": histogram_interval(hours),
        }
    }


def _base(hours: int) -> dict[str, Any]:
    return {
        "size": 0,
        "track_total_hits": True,
        "query": time_window(hours),
    }


# --------------------------------------------------------------------------- #
# Request builders
# --------------------------------------------------------------------------- #


def decoder_counts_query(hours: int) -> dict[str, Any]:
    """Per (agent, category): all events, and the no-dataset share, by hour."""
    body = _base(hours)
    body["aggs"] = {
        "agents": {
            "terms": {"field": EVENTS_AGENT_NAME_FIELD, "size": AGENT_TERMS_SIZE},
            "aggs": {
                "categories": {
                    "terms": {
                        "field": EVENTS_CATEGORY_FIELD,
                        "size": CATEGORY_TERMS_SIZE,
                    },
                    "aggs": {
                        "thin": {
                            "filter": no_dataset_filter(),
                            "aggs": {"hours": _date_histogram(hours)},
                        }
                    },
                }
            },
        }
    }
    return body


def detection_counts_query(hours: int) -> dict[str, Any]:
    """Per (agent, category): all events by hour, plus the top concrete sources."""
    body = _base(hours)
    body["aggs"] = {
        "agents": {
            "terms": {"field": EVENTS_AGENT_NAME_FIELD, "size": AGENT_TERMS_SIZE},
            "aggs": {
                "categories": {
                    "terms": {
                        "field": EVENTS_CATEGORY_FIELD,
                        "size": CATEGORY_TERMS_SIZE,
                    },
                    "aggs": {
                        "hours": _date_histogram(hours),
                        "datasets": {
                            "terms": {
                                "field": EVENTS_DATASET_FIELD,
                                "size": DATASET_FACET_SIZE,
                            }
                        },
                    },
                }
            },
        }
    }
    return body


def findings_counts_query(hours: int) -> dict[str, Any]:
    """Per (agent, category) finding counts in the window, for detection_gap."""
    body = _base(hours)
    body["aggs"] = {
        "agents": {
            "terms": {"field": EVENTS_AGENT_NAME_FIELD, "size": AGENT_TERMS_SIZE},
            "aggs": {
                "categories": {
                    "terms": {
                        "field": EVENTS_CATEGORY_FIELD,
                        "size": CATEGORY_TERMS_SIZE,
                    }
                }
            },
        }
    }
    return body


def samples_query(
    hours: int,
    kept: Sequence[tuple[str, str]],
    *,
    thin: bool,
    sample_size: int,
) -> dict[str, Any]:
    """One request that fetches raw samples for exactly the kept (agent, cat).

    Restricting the terms aggs with an exact-key `include` list means only the
    kept leaves carry a nested top_hits — the payload stays proportional to the
    report, not to the whole index. `thin` scopes the samples to the decoder_gap
    subset (no event.dataset); otherwise they are any events of the group.
    """
    include_by_agent: dict[str, list[str]] = {}
    for agent, category in kept:
        include_by_agent.setdefault(agent, []).append(category)
    all_categories = sorted({c for cats in include_by_agent.values() for c in cats})

    categories: dict[str, Any] = {
        "terms": {"field": EVENTS_CATEGORY_FIELD, "size": len(all_categories)},
    }
    # Nested terms per agent: an exact-key include list keeps the query to the
    # kept categories only (a category not under a given agent simply has no
    # bucket for it).
    categories["terms"]["include"] = all_categories

    samples: dict[str, Any] = {
        "samples": {
            "top_hits": {
                "size": sample_size,
                "_source": {"includes": ["event.original"]},
            }
        }
    }
    categories["aggs"] = (
        {"thin": {"filter": no_dataset_filter(), "aggs": samples}}
        if thin
        else samples
    )
    agents: dict[str, Any] = {
        "terms": {
            "field": EVENTS_AGENT_NAME_FIELD,
            "size": len(include_by_agent),
            "include": sorted(include_by_agent),
        },
        "aggs": {"categories": categories},
    }

    body = _base(hours)
    body["aggs"] = {"agents": agents}
    return body


# --------------------------------------------------------------------------- #
# Response parsing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Leaf:
    """One (agent, category) from the counts pass, before min_count/top_n."""

    agent: str
    category: str
    total: int  # every event of the leaf in the window
    scope: int  # the classification's scope: no-dataset events, or == total
    hours: tuple[tuple[str, int], ...] = ()  # (bucket label, count), in scope
    datasets: tuple[str, ...] = ()  # detection only: concrete sources in the leaf


def _agent_buckets(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    aggs = payload.get("aggregations")
    if not isinstance(aggs, dict):
        return []
    agents = aggs.get("agents")
    if not isinstance(agents, dict):
        return []
    raw = agents.get("buckets")
    if not isinstance(raw, list):
        return []
    return [b for b in raw if isinstance(b, dict)]


def _category_buckets(agent: dict[str, Any]) -> list[dict[str, Any]]:
    """The category buckets nested directly inside an agent bucket.

    OpenSearch nests a bucket's sub-aggregations DIRECTLY in the bucket as
    siblings of `key`/`doc_count` — there is no `aggs` wrapper (the trap this
    repo documents in anonymization.py).
    """
    node = agent.get("categories")
    if not isinstance(node, dict):
        return []
    raw = node.get("buckets")
    if not isinstance(raw, list):
        return []
    return [b for b in raw if isinstance(b, dict)]


def _doc_count(node: Any) -> int:
    if isinstance(node, dict):
        value = node.get("doc_count")
        if isinstance(value, int):
            return value
    return 0


def _hour_buckets(node: Any) -> tuple[tuple[str, int], ...]:
    if not isinstance(node, dict):
        return ()
    raw = node.get("buckets")
    if not isinstance(raw, list):
        return ()
    out: list[tuple[str, int]] = []
    for bucket in raw:
        if not isinstance(bucket, dict):
            continue
        count = bucket.get("doc_count")
        if not isinstance(count, int) or count <= 0:
            continue
        label = bucket.get("key_as_string")
        out.append((label if isinstance(label, str) else str(bucket.get("key")), count))
    return tuple(out)


def _dataset_keys(node: Any) -> tuple[str, ...]:
    if not isinstance(node, dict):
        return ()
    raw = node.get("buckets")
    if not isinstance(raw, list):
        return ()
    return tuple(str(b.get("key")) for b in raw if isinstance(b, dict))


def _leaf(agent: str, category: dict[str, Any], *, thin: bool) -> Leaf:
    """One leaf out of the counts pass.

    The leaf's own bucket doc_count is every event of the (agent, category) in
    the window. In the decoder tree the classification's scope is the count of
    no-dataset events (the nested `thin` filter); in the detection tree the
    scope is the whole leaf, and the extra `datasets` facet is carried along.
    Sub-aggregations are read as direct bucket children (no `aggs` wrapper).
    """
    key = category.get("key")
    label = str(key)
    total = _doc_count(category)
    if thin:
        thin_node = category.get("thin")
        scope = _doc_count(thin_node)
        hours: tuple[tuple[str, int], ...] = ()
        if isinstance(thin_node, dict):
            hours = _hour_buckets(thin_node.get("hours"))
        return Leaf(agent, label, total, scope, hours)
    return Leaf(
        agent,
        label,
        total,
        total,
        _hour_buckets(category.get("hours")),
        _dataset_keys(category.get("datasets")),
    )


def parse_counts(payload: Any, *, thin: bool) -> list[Leaf]:
    """Leaves of the counts pass. `thin` selects the decoder_gap tree shape."""
    leaves: list[Leaf] = []
    for agent_bucket in _agent_buckets(payload):
        agent = agent_bucket.get("key")
        if not isinstance(agent, str):
            continue
        for category in _category_buckets(agent_bucket):
            key = category.get("key")
            if key is None:
                continue
            leaves.append(_leaf(agent, category, thin=thin))
    return leaves


def parse_findings(payload: Any) -> tuple[dict[tuple[str, str], int], int]:
    """Per-(agent, category) finding counts plus the window total."""
    counts: dict[tuple[str, str], int] = {}
    total = 0
    if isinstance(payload, dict):
        hits = payload.get("hits")
        if isinstance(hits, dict):
            node = hits.get("total")
            if isinstance(node, int):
                total = node
            elif isinstance(node, dict) and isinstance(node.get("value"), int):
                total = node["value"]
    for agent_bucket in _agent_buckets(payload):
        agent = agent_bucket.get("key")
        if not isinstance(agent, str):
            continue
        for category in _category_buckets(agent_bucket):
            key = category.get("key")
            if not isinstance(key, str):
                continue
            counts[(agent, key)] = _doc_count(category)
    return counts, total


def _raw_line(source: dict[str, Any]) -> str | None:
    """The event.original raw line, in either representation WCS can store.

    Real Wazuh 5 documents nest it (`event: {original: ...}`); some decoder
    generations flatten it to a literal `event.original` key. The same
    tolerance the repo applies everywhere else (`source_has_path`, gdpr._collect)
    applies here — guessing one shape would silently drop every sample from the
    other.
    """
    nested = source.get("event")
    if isinstance(nested, dict):
        value = nested.get("original")
        if isinstance(value, str) and value:
            return value
    value = source.get("event.original")
    if isinstance(value, str) and value:
        return value
    return None


def parse_samples(
    payload: Any, agent: str, category: str, *, thin: bool
) -> tuple[str, ...]:
    """The raw event.original lines a kept group's top_hits returned."""
    out: list[str] = []
    for agent_bucket in _agent_buckets(payload):
        if agent_bucket.get("key") != agent:
            continue
        for cat in _category_buckets(agent_bucket):
            if cat.get("key") != category:
                continue
            node: Any = cat
            if thin:
                thin_node = cat.get("thin")
                if not isinstance(thin_node, dict):
                    return tuple(out)
                node = thin_node
            samples = node.get("samples")
            if isinstance(samples, dict):
                hits = samples.get("hits")
                if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
                    for hit in hits["hits"]:
                        if not isinstance(hit, dict):
                            continue
                        source = hit.get("_source")
                        if not isinstance(source, dict):
                            continue
                        line = _raw_line(source)
                        if line:
                            out.append(line)
            return tuple(out)
    return tuple(out)


# --------------------------------------------------------------------------- #
# Selection and group summaries
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Group:
    """One reported row: a source (agent, category) with its gap profile."""

    agent: str
    category: str
    count: int  # events in the classification's scope (thin / all)
    total: int  # every event of the leaf in the window
    findings: int = 0  # detection_gap: findings in the window (0 == the gap)
    active: int = 0  # histogram buckets holding events
    expected: int = 0  # histogram buckets a full window spans
    peak: int = 0
    peak_at: str = MISSING
    sustained: bool = False
    datasets: tuple[str, ...] = ()
    samples: tuple[str, ...] = ()


@dataclass(frozen=True)
class Selection:
    kind: str
    groups: tuple[Group, ...]
    leaves_total: int
    kept_candidates: int  # passed the scope filter, before the top_n slice
    findings_positive: int = 0  # detection only: groups with findings, excluded


def _summarize(leaf: Leaf, *, hours: int, count: int, findings: int = 0) -> Group:
    """Fold one kept leaf into a display row with its time profile."""
    active = len(leaf.hours)
    expected = expected_buckets(hours)
    peak = 0
    peak_at = MISSING
    if leaf.hours:
        peak_label, peak_count = max(leaf.hours, key=lambda item: item[1])
        peak = peak_count
        peak_at = peak_label
    sustained = active > 0 and active >= max(1, round(expected * SUSTAINED_FRACTION))
    return Group(
        agent=leaf.agent,
        category=leaf.category,
        count=count,
        total=leaf.total,
        findings=findings,
        active=active,
        expected=expected,
        peak=peak,
        peak_at=peak_at,
        sustained=sustained,
        datasets=leaf.datasets,
    )


def select_groups(
    leaves: Sequence[Leaf],
    *,
    kind: str,
    hours: int,
    min_count: int,
    top_n: int,
    findings: Mapping[tuple[str, str], int] | None = None,
) -> Selection:
    """Filter to real gaps, sort by size descending, cap at top_n.

    decoder_gap: a leaf is a gap when its no-dataset count is >= min_count.
    detection_gap: a leaf is a gap when it has >= min_count events and ZERO
    findings in the window (leaves that did produce findings are the healthy
    ones and are excluded, but counted for the notice).
    """
    findings = findings or {}
    if kind == CLASSIFICATION_DECODER_GAP:
        eligible = [(leaf, leaf.scope) for leaf in leaves if leaf.scope >= min_count]
        ordered = sorted(eligible, key=lambda item: (-item[1], -item[0].total, item[0].agent, item[0].category))
        findings_positive = 0
    else:
        positive = 0
        eligible = []
        for leaf in leaves:
            fcount = findings.get((leaf.agent, leaf.category), 0)
            if fcount > 0:
                positive += 1
                continue
            if leaf.total >= min_count:
                eligible.append((leaf, leaf.total))
        ordered = sorted(eligible, key=lambda item: (-item[1], item[0].agent, item[0].category))
        findings_positive = positive

    kept = min(len(ordered), top_n)
    groups = tuple(
        _summarize(leaf, hours=hours, count=count, findings=findings.get((leaf.agent, leaf.category), 0))
        for leaf, count in ordered[:kept]
    )
    return Selection(
        kind=kind,
        groups=groups,
        leaves_total=len(leaves),
        kept_candidates=len(ordered),
        findings_positive=findings_positive,
    )


def with_samples(
    groups: Sequence[Group], samples: Mapping[tuple[str, str], Sequence[str]]
) -> tuple[Group, ...]:
    """Return the groups with their raw sample lines attached."""
    return tuple(
        replace(g, samples=tuple(samples.get((g.agent, g.category), ())))
        for g in groups
    )


def mask_groups(
    groups: Sequence[Group],
    agent_names: Mapping[str, str],
    mask_line: Callable[[str], str],
) -> tuple[Group, ...]:
    """Route a report through the pseudonymization layer before rendering.

    `agent_names` maps each raw agent name to its token (findings_overview
    masks its agent rows the same way — a hostname in a table key is masked
    exactly like the same value in `_source`); `mask_line` masks one raw
    sample line (the anonymizer's free-text pass). Values not in the map, and
    already-token values, pass through unchanged.
    """
    return tuple(
        replace(
            g,
            agent=agent_names.get(g.agent, g.agent),
            samples=tuple(mask_line(s) for s in g.samples),
        )
        for g in groups
    )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _share(count: int, total: int) -> str:
    if total <= 0:
        return MISSING
    if count == total:
        return "100.0%"
    return f"{(count / total) * 100:.1f}%"


def _active_label(active: int, expected: int) -> str:
    return f"{active}/{expected}"


def _samples_block(groups: Sequence[Group]) -> str:
    blocks: list[str] = []
    for group in groups:
        if not group.samples:
            continue
        lines = [f"samples — {group.agent} / {group.category}:"]
        lines.extend(f"  {s}" for s in group.samples)
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def render_decoder(groups: Sequence[Group]) -> str:
    """The decoder-gap section: sources whose events were never mapped to a dataset."""
    heading = (
        "=== DECODER GAPS ===\n"
        f"Events with a raw line but no {EVENTS_DATASET_FIELD} — decoded only by a "
        "generic decoder, not mapped to an integration dataset. SHARE is the share "
        "of the group's events that are gap events; ACTIVE is "
        "hours-with-events/full-window-hours."
    )
    if not groups:
        return heading + "\n" + "(no decoder-gap groups in the window)"
    body = table(
        [
            "AGENT",
            "CATEGORY",
            "GAP_EVENTS",
            "TOTAL",
            "SHARE",
            "ACTIVE",
            "PEAK",
            "PEAK_AT(UTC)",
            "SUSTAINED",
        ],
        [
            [
                g.agent,
                g.category,
                str(g.count),
                str(g.total),
                _share(g.count, g.total),
                _active_label(g.active, g.expected),
                str(g.peak),
                g.peak_at,
                "yes" if g.sustained else "no",
            ]
            for g in groups
        ],
        right=(2, 3, 4, 5, 6),
    )
    samples = _samples_block(groups)
    return heading + "\n" + body + (("\n\n" + samples) if samples else "")


def render_detection(groups: Sequence[Group]) -> str:
    """The detection-gap section: events present, findings absent, per source."""
    heading = (
        "=== DETECTION GAPS ===\n"
        f"Sources that produced events in the window but ZERO findings in "
        f"{FINDINGS_PATTERN} for the same window — normalised, but nothing was "
        f"detected from them. TOP_SOURCES lists the concrete {EVENTS_DATASET_FIELD} "
        f"values inside the (coarse) category."
    )
    if not groups:
        return heading + "\n" + "(no detection-gap groups in the window)"
    body = table(
        [
            "AGENT",
            "CATEGORY",
            "EVENTS",
            "FINDINGS",
            "TOP_SOURCES",
            "ACTIVE",
            "PEAK",
            "PEAK_AT(UTC)",
            "SUSTAINED",
        ],
        [
            [
                g.agent,
                g.category,
                str(g.count),
                str(g.findings),
                ", ".join(g.datasets) if g.datasets else MISSING,
                _active_label(g.active, g.expected),
                str(g.peak),
                g.peak_at,
                "yes" if g.sustained else "no",
            ]
            for g in groups
        ],
        right=(2, 3, 5, 6),
    )
    samples = _samples_block(groups)
    return heading + "\n" + body + (("\n\n" + samples) if samples else "")


def header(
    hours: int,
    window_total: int | None,
    grand_total: int | None,
    findings_total: int | None,
) -> str:
    """The block above the sections: what was asked, and over what."""
    lines = [
        f"index:          {EVENTS_PATTERN}",
        f"window:         last {hours}h ({TIME_FIELD} >= now-{hours}h)",
        f"events:         {'(not queried)' if window_total is None else window_total} in window"
        + (f", {grand_total} index-wide" if grand_total is not None else ""),
    ]
    if findings_total is not None:
        lines.append(
            f"findings:       {findings_total} in window ({FINDINGS_PATTERN})"
        )
    return "\n".join(lines)
