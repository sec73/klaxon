# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Field discovery for the `schema` and `field_coverage` tools.

_field_caps answers "what is mapped". It does not answer "what carries data",
and in the Wazuh 5 schema those two questions have very different answers: both
`agent.id` and `wazuh.agent.id` are mapped as keyword, only the latter is ever
populated. Discovering that difference requires a second pass with exists
aggregations, which is what this module does.

And an exists aggregation does not answer it either, for a field the mapping
declares unindexed. Verified on a live instance:

    event.original in wazuh-events-v5-network-activity*
      mapping          {"type": "keyword", "index": false, "doc_values": false}
      exists           0 of 10,243,389 documents
      _source          the complete raw log line, in every document sampled

The zero is a property of the mapping, not of the data. So this module also
reads the declared mapping — which fields exists can answer for at all — and can
sample _source for the ones it cannot, because "not measurable" is a more useful
answer when it comes with evidence that the value is nonetheless there.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .clients import IndexerClient, Response


@dataclass
class FieldInfo:
    name: str
    types: list[str] = field(default_factory=list)
    doc_count: int | None = None  # None when not probed

    @property
    def type_label(self) -> str:
        if not self.types:
            return "unknown"
        if len(self.types) == 1:
            return self.types[0]
        return "CONFLICT:" + "|".join(sorted(self.types))


@dataclass
class FieldCapsResult:
    ok: bool
    fields: list[FieldInfo]
    response: Response


def parse_field_caps(response: Response) -> FieldCapsResult:
    """Turn a _field_caps response into a sorted list of FieldInfo."""
    if not response.ok:
        return FieldCapsResult(ok=False, fields=[], response=response)

    parsed = response.json()
    if not isinstance(parsed, dict):
        return FieldCapsResult(ok=False, fields=[], response=response)

    raw = parsed.get("fields")
    if not isinstance(raw, dict):
        return FieldCapsResult(ok=True, fields=[], response=response)

    out: list[FieldInfo] = []
    for name, caps in raw.items():
        if not isinstance(name, str) or name.startswith("_"):
            # Skip metadata fields (_index, _id, _seq_no, ...).
            continue
        types = sorted(caps.keys()) if isinstance(caps, dict) else []
        out.append(FieldInfo(name=name, types=[str(t) for t in types]))

    out.sort(key=lambda f: f.name)
    return FieldCapsResult(ok=True, fields=out, response=response)


async def fetch_field_caps(
    client: IndexerClient, index: str, prefix: str | None
) -> FieldCapsResult:
    """GET /{index}/_field_caps?fields={prefix}*"""
    pattern = f"{prefix}*" if prefix else "*"
    response = await client.get(f"/{index}/_field_caps", params={"fields": pattern})
    return parse_field_caps(response)


def build_exists_aggs(names: list[str]) -> dict[str, Any]:
    """Build a filter/exists aggregation per candidate field.

    A filter+exists aggregation is used rather than value_count because it works
    for every field type, including text fields where doc_values are disabled.
    """
    return {
        f"f{i}": {"filter": {"exists": {"field": name}}} for i, name in enumerate(names)
    }


def parse_exists_aggs(response: Response, names: list[str]) -> dict[str, int]:
    """Map the aggregation results back onto field names."""
    counts: dict[str, int] = {}
    parsed = response.json()
    if not isinstance(parsed, dict):
        return counts
    aggs = parsed.get("aggregations")
    if not isinstance(aggs, dict):
        return counts

    for i, name in enumerate(names):
        node = aggs.get(f"f{i}")
        if isinstance(node, dict) and isinstance(node.get("doc_count"), int):
            counts[name] = node["doc_count"]
    return counts


async def probe_population(
    client: IndexerClient,
    index: str,
    fields: list[FieldInfo],
    *,
    batch_size: int,
    query: dict[str, Any] | None = None,
) -> tuple[dict[str, int], list[Response]]:
    """Count documents holding a value for each field, in batched requests.

    `query` narrows what "documents" means — a time range, typically. The
    default of match_all measures the whole datastream, which is the right
    denominator for "is this field ever populated" and the wrong one for "is it
    populated now": a datastream spans decoder generations, and a field fixed
    this morning still reads near zero across months of older documents.
    """
    counts: dict[str, int] = {}
    failures: list[Response] = []

    for start in range(0, len(fields), batch_size):
        chunk = [f.name for f in fields[start : start + batch_size]]
        body: dict[str, Any] = {
            "size": 0,
            "track_total_hits": True,
            "query": query if query is not None else {"match_all": {}},
            "aggs": build_exists_aggs(chunk),
        }
        response = await client.post(f"/{index}/_search", body=body)
        if not response.ok:
            failures.append(response)
            continue
        counts.update(parse_exists_aggs(response, chunk))

    return counts, failures


def parse_total(response: Response) -> int | None:
    """Read hits.total.value, or None when the response does not carry one.

    None is not zero. A denominator that could not be read has to stay absent
    all the way into the output, or every coverage percentage below it becomes
    a number derived from a guess.
    """
    parsed = response.json()
    if not isinstance(parsed, dict):
        return None
    hits = parsed.get("hits")
    if not isinstance(hits, dict):
        return None
    total = hits.get("total")
    if isinstance(total, int):
        return total
    if isinstance(total, dict) and isinstance(total.get("value"), int):
        value: int = total["value"]
        return value
    return None


# --------------------------------------------------------------------------- #
# What the mapping allows exists to answer
# --------------------------------------------------------------------------- #


@dataclass
class FieldMappingFacts:
    """How a field is declared, counted across the indices that declare it.

    A datastream is many backing indices, and they need not agree — a rollover
    can carry a changed mapping. So these are counts, not booleans: a field that
    is unindexed in one generation and indexed in the next is measurable, but
    only over part of the data, and that is a third answer again.
    """

    declared_in: int = 0
    unindexed_in: int = 0
    doc_values_disabled_in: int = 0

    @property
    def unindexed(self) -> bool:
        """True when no index that declares this field indexes it."""
        return self.declared_in > 0 and self.unindexed_in == self.declared_in

    @property
    def partially_indexed(self) -> bool:
        return 0 < self.unindexed_in < self.declared_in

    @property
    def doc_values_disabled(self) -> bool:
        return self.doc_values_disabled_in > 0


def parse_field_mappings(response: Response) -> dict[str, FieldMappingFacts]:
    """Read GET /{index}/_mapping/field/{pattern} into per-field declarations.

    The response nests the declaration under a key that is the *last segment* of
    the field name — `event.original` arrives as
    `{"mapping": {"original": {...}}}` — so the leaf is taken as the sole value
    of that object rather than by name.
    """
    facts: dict[str, FieldMappingFacts] = {}
    parsed = response.json()
    if not isinstance(parsed, dict):
        return facts

    for node in parsed.values():
        if not isinstance(node, dict):
            continue
        mappings = node.get("mappings")
        if not isinstance(mappings, dict):
            continue
        for full_name, entry in mappings.items():
            if not isinstance(full_name, str) or not isinstance(entry, dict):
                continue
            declared = entry.get("mapping")
            leaf: dict[str, Any] = {}
            if isinstance(declared, dict) and len(declared) == 1:
                candidate = next(iter(declared.values()))
                if isinstance(candidate, dict):
                    leaf = candidate

            item = facts.setdefault(full_name, FieldMappingFacts())
            item.declared_in += 1
            # `enabled: false` on an object switches off indexing for everything
            # underneath it, with the same consequence for exists.
            if leaf.get("index") is False or leaf.get("enabled") is False:
                item.unindexed_in += 1
            if leaf.get("doc_values") is False:
                item.doc_values_disabled_in += 1

    return facts


async def fetch_field_mappings(
    client: IndexerClient, index: str, prefix: str | None
) -> tuple[dict[str, FieldMappingFacts], Response]:
    """GET /{index}/_mapping/field/{prefix}*

    The field-scoped form of the mapping API rather than the whole mapping: the
    engine schema has 2351 fields across every backing index, and only the ones
    about to be measured matter here.
    """
    pattern = f"{prefix}*" if prefix else "*"
    response = await client.get(f"/{index}/_mapping/field/{pattern}")
    if not response.ok:
        return {}, response
    return parse_field_mappings(response), response


# --------------------------------------------------------------------------- #
# _source sampling, for the fields exists cannot reach
# --------------------------------------------------------------------------- #


def source_has_path(node: Any, path: str) -> bool:
    """Whether a dotted path is present and non-empty in a _source document.

    Both shapes are accepted: nested objects, and a literal dotted key. Which of
    the two a document uses is a decoder decision, and guessing wrong would turn
    a present value into an absent one — the mistake this whole check exists to
    correct.
    """
    if isinstance(node, list):
        return any(source_has_path(item, path) for item in node)
    if not isinstance(node, dict):
        return False

    segments = path.split(".")
    for i in range(1, len(segments) + 1):
        key = ".".join(segments[:i])
        if key not in node:
            continue
        value = node[key]
        rest = ".".join(segments[i:])
        if not rest:
            if value is not None and value != [] and value != {}:
                return True
            continue
        if source_has_path(value, rest):
            return True
    return False


async def sample_source(
    client: IndexerClient,
    index: str,
    names: list[str],
    *,
    size: int,
    query: dict[str, Any] | None = None,
) -> tuple[dict[str, int], int, Response]:
    """Count, over a small sample of documents, which of `names` _source holds.

    Returns (hits per field, documents sampled, response). A sample is not a
    coverage figure and must never be rendered as one — it answers "is this
    field there at all", which for an unindexed field is the only question that
    can still be answered.
    """
    body: dict[str, Any] = {
        "size": size,
        "_source": {"includes": names},
        "query": query if query is not None else {"match_all": {}},
        "track_total_hits": False,
    }
    response = await client.post(f"/{index}/_search", body=body)
    if not response.ok:
        return {}, 0, response

    parsed = response.json()
    hits: list[Any] = []
    if isinstance(parsed, dict):
        node = parsed.get("hits")
        if isinstance(node, dict) and isinstance(node.get("hits"), list):
            hits = node["hits"]

    counts = {name: 0 for name in names}
    for hit in hits:
        source = hit.get("_source") if isinstance(hit, dict) else None
        if source is None:
            continue
        for name in names:
            if source_has_path(source, name):
                counts[name] += 1

    return counts, len(hits), response


async def count_documents(
    client: IndexerClient, index: str, query: dict[str, Any] | None = None
) -> tuple[int | None, Response]:
    """Exact document count for a query. `track_total_hits` is not optional.

    Without it OpenSearch stops counting at TOTAL_HITS_CAP and reports a lower
    bound, which as the denominator of a coverage percentage would silently
    inflate every field in the table.
    """
    body: dict[str, Any] = {
        "size": 0,
        "track_total_hits": True,
        "query": query if query is not None else {"match_all": {}},
    }
    response = await client.post(f"/{index}/_search", body=body)
    if not response.ok:
        return None, response
    return parse_total(response), response
