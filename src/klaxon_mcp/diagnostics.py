# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The layer that turns silent emptiness into an explicit statement.

Design rule of this project: a silently wrong answer is worse than a clean
error. OpenSearch answers a query against a non-existent wildcard pattern with
an empty hit list and HTTP 200; it answers a terms aggregation on an unpopulated
field with zero buckets and HTTP 200. Both predecessor servers rendered those as
"no alerts found".

Nothing in here rewrites or reformats the response payload. Notices are
assembled into a preamble and the raw JSON is appended verbatim underneath, so
the caller still sees exactly what the API said.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from .clients import Response
from .config import AnonymizationConfig
from .constants import (
    EVENTS_PATTERN,
    FINDINGS_PATTERN,
    LEGACY_4X_PATTERNS,
    SHADOWED_NAMESPACES,
    SUGGESTED_PATTERNS,
    TESTER_SESSION_STATES,
    TOTAL_HITS_CAP,
)

PREAMBLE_HEADER = "=== DIAGNOSTICS (added by Klaxon MCP; not part of the API response) ==="
RAW_HEADER = "=== RAW RESPONSE ==="

SEARCH_SIZE_ENV = "KLAXON_SEARCH_MAX_SIZE"

# The raw Wazuh 5 streams carry unmasked personal data. A query that targets one
# of these (or a sub-pattern of them) is a RAW STREAM QUERY unless it goes to a
# masked stream (klaxon-masked-<tenant>-v5*). Derived from the canonical
# pattern constants so the two never drift.
_RAW_STREAM_PREFIXES = tuple(
    p.removesuffix("-*") for p in (EVENTS_PATTERN, FINDINGS_PATTERN)
)


def _matches_any(index: str, patterns: tuple[str, ...]) -> bool:
    """Glob-match an index against the configured `masked_streams` allowlist."""
    lowered = index.lower()
    return any(fnmatch.fnmatchcase(lowered, p.lower()) for p in patterns)


def _is_raw_stream(index: str, masked_streams: tuple[str, ...] = ()) -> bool:
    """Whether an index pattern targets a raw Wazuh 5 stream (events/findings).

    Raw-vs-masked is decided against the EFFECTIVE `masked_streams` value: an
    index that matches a configured masked stream is explicitly recognised as
    masked (never flagged raw) even though the raw namespaces (`wazuh-events-*`,
    `wazuh-findings-*`) do not currently overlap `klaxon-masked-*`. This keeps
    the banner aligned with the allowlist, so a query that resolves to the
    masked data stream never shows `[RAW STREAM QUERY]`.
    """
    if _matches_any(index, masked_streams):
        return False
    lowered = index.lower()
    return any(lowered.startswith(prefix) for prefix in _RAW_STREAM_PREFIXES)


def safety_banner(cfg: AnonymizationConfig, index: str) -> list[str]:
    """Safety lines prepended to every search response when it is not protected.

    Three conditions, each emitting one banner line when it holds:

    1. Masking is off (the feature is disabled, or no fields are configured) —
       the response is returned unmasked.
    2. The LLM endpoint is not local (no loopback) and the response gate
       (residual-PII whitelist) is inactive — residual personal data is not
       blocked before it reaches an external model.
    3. The query targeted a raw Wazuh stream (`wazuh-events-v5-*` /
       `wazuh-findings-v5-*`) instead of a masked stream
       (`klaxon-masked-<tenant>-v5*`) — raw personal data may be present.

    The banner is emitted automatically, before any other diagnostics, on EVERY
    response that meets a condition — including zero-hit, error,
    aggregation-only and paginated responses — so it cannot be forgotten. It
    never contains values, tokens, salts or PII: only the condition and a
    reason.
    """
    lines: list[str] = []

    # Condition 1: the masking feature is off, or no fields are configured.
    if not cfg.enabled or not cfg.mask_fields:
        lines.append(
            "[UNMASKED MODE] Anonymization is disabled — personal data in this "
            "response is returned unmasked."
        )

    # Condition 2: an external LLM (non-loopback) with the response gate off.
    if not cfg.llm_is_local and not cfg.whitelist_enabled:
        lines.append(
            "[UNMASKED MODE] The LLM endpoint is not local (no loopback) and the "
            "response gate is inactive — residual personal data is not blocked "
            "before reaching the external model."
        )

    # Condition 3: the query targeted a raw Wazuh stream instead of a masked one.
    if _is_raw_stream(index, cfg.masked_streams):
        masked = ", ".join(cfg.masked_streams) if cfg.masked_streams else "none configured"
        lines.append(
            f"[RAW STREAM QUERY] This query targeted {index!r} (raw); the masked "
            f"stream ({masked}) is not deployed/selected — raw personal data may "
            "be present in this response."
        )

    return lines


def size_capped_notice(requested: int, effective: int) -> str:
    """State that the request body was lowered before the query was sent.

    The one notice in here that describes the *request* rather than the response.
    Capping is the only point where this server changes what the caller asked
    for, so it is also the one place where staying silent would reproduce exactly
    the failure the rest of this module exists to prevent: a caller asking for
    500 documents, receiving 100, and reading them as the whole result.
    """
    return (
        f"[SIZE CAPPED] The body requested \"size\": {requested}; the query was sent "
        f"with \"size\": {effective} instead. The documents in hits.hits are the "
        f"first {effective} of the match, not the {requested} asked for — do not "
        f"read them as the complete result set. hits.total is unaffected and still "
        f"reports the real match count. Raise the cap with the {SEARCH_SIZE_ENV} "
        f"environment variable (currently {effective}), or page through the result "
        f"set with search_after."
    )


def agg_size_capped_notice(capped: list[tuple[str, int]], effective: int) -> str:
    """State that aggregation `size` values were lowered before the query went out.

    `capped` is `(aggregation_name, requested_size)` for every aggregation that
    was lowered. The top-level `size` cap bounds the number of documents, but
    not the number of buckets an aggregation returns — a
    `terms`/`composite`/`top_hits` with `"size": 100000` could otherwise force a
    huge response that is then walked (and masked) in full. The same cap as the
    document size keeps the response bounded and therefore the masking pass
    bounded. Like `size_capped_notice`, both the requested and the effective
    numbers are stated, so a lowered bucket count is never read as the real one.
    """
    lowered = "; ".join(
        f"{name} requested {requested}" for name, requested in capped
    )
    return (
        f"[AGG SIZE CAPPED] The following aggregation sizes were lowered before "
        f"the query was sent: {lowered} — each was sent with \"size\": {effective}. "
        f"Raise the cap with the {SEARCH_SIZE_ENV} environment variable."
    )


def unmappable_agg_dropped_notice(pairs: list[tuple[str, str]]) -> str:
    """State that unmappable aggregations were stripped from the request.

    The "drop" mode of `block_unmappable_aggs`: an aggregation whose output the
    anonymizer cannot guarantee to mask (`scripted_metric`, any unknown type)
    is removed from the request before it is executed, so the response cannot
    carry its raw values. Like the size-cap notices, this one describes the
    REQUEST rather than the response — staying silent would let the caller read
    the stripped response as the whole answer.
    """
    names = "; ".join(f"{agg_type} ({name})" for name, agg_type in pairs)
    return (
        f"[UNMAPPABLE AGG DROPPED] Aggregation(s) whose output cannot be "
        f"anonymised were removed from the request before it was sent: {names}. "
        f"Their results are absent from this response. Rewrite the query without "
        f"these aggregations, or raise the data-protection exception explicitly "
        f"(anonymization.block_unmappable_aggs)."
    )


def unmappable_feature_dropped_notice(pairs: list[tuple[str, str]]) -> str:
    """State that opaque request features were stripped from the request.

    The "drop" mode of `block_unmappable_features`: a request section whose
    output the anonymizer cannot guarantee to mask (`runtime_mappings`,
    `script_fields`, `suggest`, `highlight`) is removed from the request before
    it is executed, so the response cannot carry its raw values. Like the
    size-cap notices, this one describes the REQUEST rather than the response —
    staying silent would let the caller read the stripped response as the whole
    answer.
    """
    names = "; ".join(name for name, _ in pairs)
    return (
        f"[UNMAPPABLE FEATURE DROPPED] Request feature(s) whose output cannot "
        f"be anonymised were removed from the request before it was sent: "
        f"{names}. Their results are absent from this response. Rewrite the "
        f"query without these features, or raise the data-protection exception "
        f"explicitly (anonymization.block_unmappable_features)."
    )


def _total(hits: Any) -> tuple[int | None, str | None]:
    """Extract (value, relation) from hits.total across both response shapes."""
    if not isinstance(hits, dict):
        return None, None
    total = hits.get("total")
    if isinstance(total, int):
        return total, None
    if isinstance(total, dict):
        value = total.get("value")
        relation = total.get("relation")
        return (
            value if isinstance(value, int) else None,
            relation if isinstance(relation, str) else None,
        )
    return None, None


def _walk_bucket_aggs(
    aggs: Any, scope: int, path: str = ""
) -> list[tuple[str, list[dict[str, Any]], int, int]]:
    """Collect (name, buckets, sum_other_doc_count, scope) for every bucketed agg.

    `scope` is the number of documents the aggregation was actually computed
    over: hits.total at the top level, the parent bucket's doc_count inside a
    terms bucket, and a single-bucket agg's own doc_count inside a filter. A
    nested aggregation can never cover more documents than its parent, so
    measuring it against hits.total reports a gap that does not exist.
    """
    found: list[tuple[str, list[dict[str, Any]], int, int]] = []
    if not isinstance(aggs, dict):
        return found

    for name, node in aggs.items():
        if not isinstance(node, dict):
            continue
        full = f"{path}{name}"
        buckets = node.get("buckets")
        if isinstance(buckets, list):
            other = node.get("sum_other_doc_count")
            found.append((full, buckets, other if isinstance(other, int) else 0, scope))
            for bucket in buckets:
                if isinstance(bucket, dict):
                    inner = bucket.get("doc_count")
                    found.extend(
                        _walk_bucket_aggs(
                            bucket,
                            inner if isinstance(inner, int) else scope,
                            f"{full}>",
                        )
                    )
        else:
            # Single-bucket aggregation (filter, nested, global, reverse_nested):
            # its own doc_count bounds everything underneath it.
            inner = node.get("doc_count")
            found.extend(
                _walk_bucket_aggs(
                    node,
                    inner if isinstance(inner, int) else scope,
                    f"{full}>",
                )
            )
    return found


_RESERVED_AGG_KEYS = frozenset({"aggs", "aggregations", "meta"})


def _agg_field_map(body: Any) -> dict[str, str]:
    """Map each aggregation path to the field it aggregates, read off the request.

    The response carries no field names. An empty bucket list on its own says
    nothing about *which* field came back empty, so any hint keyed to a specific
    field has to be resolved against the request body.
    """
    out: dict[str, str] = {}

    def walk(aggs: Any, path: str) -> None:
        if not isinstance(aggs, dict):
            return
        for name, spec in aggs.items():
            if not isinstance(spec, dict):
                continue
            full = f"{path}{name}"
            for kind, inner in spec.items():
                if kind in _RESERVED_AGG_KEYS or not isinstance(inner, dict):
                    continue
                field = inner.get("field")
                if isinstance(field, str):
                    out[full] = field
                    break
            walk(spec.get("aggs") or spec.get("aggregations"), f"{full}>")

    if isinstance(body, dict):
        walk(body.get("aggs") or body.get("aggregations"), "")
    return out


def _shadow_hint(field: str | None) -> str:
    """Mention the shadowed-namespace trap only when the field is actually in one.

    Appending it to every empty aggregation makes the notice wrong more often
    than right, and a diagnostic that cries wolf is worse than none.
    """
    if not field:
        return ""
    for shadowed, populated in SHADOWED_NAMESPACES.items():
        if field.startswith(shadowed):
            return (
                f" {field!r} sits in the shadowed {shadowed!r} namespace: both"
                f" {shadowed!r} and {populated!r} are mapped as keyword and only"
                f" the {populated!r} branch is ever populated. Try"
                f" {field.replace(shadowed, populated, 1)!r}."
            )
    return ""


def _legacy_notice(index: str) -> str | None:
    """Flag Wazuh 4.x index patterns, which cannot match anything in 5.x."""
    lowered = index.lower()
    for legacy in LEGACY_4X_PATTERNS:
        if lowered.startswith(legacy):
            suggestions = ", ".join(SUGGESTED_PATTERNS)
            return (
                f"[WAZUH 4.x INDEX PATTERN] {index!r} is a Wazuh 4.x index name. "
                f"It does not exist in Wazuh 5: the engine enforces "
                f"'^wazuh-events-v5-...' at decoder build time and rejects "
                f"'wazuh-alerts-*' outright. An empty result here means the "
                f"pattern is wrong, not that there is no data. "
                f"Use one of: {suggestions}."
            )
    return None


def search_notices(index: str, body: Any, response: Response) -> list[str]:
    """Build the diagnostic notices for a search response."""
    notices: list[str] = []

    legacy = _legacy_notice(index)
    if legacy:
        notices.append(legacy)

    if not response.ok:
        parsed = response.json()
        kind = ""
        if isinstance(parsed, dict):
            error = parsed.get("error")
            if isinstance(error, dict):
                kind = str(error.get("type", ""))
        detail = f" ({kind})" if kind else ""
        notices.append(
            f"[HTTP {response.status_code}]{detail} The indexer rejected the search "
            f"against {index!r}. The error body can echo the query and is withheld "
            f"from masked output."
        )
        if kind == "index_not_found_exception":
            notices.append(
                f"[INDEX NOT FOUND] No index or datastream matches {index!r}. "
                "Note this is only raised for concrete names; a wildcard pattern "
                "that matches nothing returns HTTP 200 with zero hits instead."
            )
        return notices

    parsed = response.json()
    if not isinstance(parsed, dict):
        notices.append("[NON-JSON RESPONSE] The indexer returned a body that is not JSON.")
        return notices

    # A 200 response can carry a failed shard: `_shards.failures` echoes the raw
    # query (script source, field names, possibly values) and is opaque to the
    # walker. The anonymization layer strips it from masked output; the notice
    # states the count either way so a partial answer is never read as complete.
    shards = parsed.get("_shards")
    if isinstance(shards, dict) and isinstance(shards.get("failures"), list):
        failed = [f for f in shards["failures"] if f]
        if failed:
            notices.append(
                f"[SHARD FAILURES] {len(failed)} shard(s) failed; this response "
                "is partial. Failure details echo the query and are withheld "
                "from masked output."
            )

    hits = parsed.get("hits")
    value, relation = _total(hits)

    if value == 0:
        notices.append(
            f"[ZERO HITS] The index pattern {index!r} matched 0 documents. "
            "This is a successful query that found nothing — it does not "
            "distinguish between 'no data in range' and 'the pattern matches no "
            "index at all'. A wildcard that matches no datastream returns exactly "
            "this response. Verify the pattern before concluding there is no data."
        )

    if relation == "gte":
        track = _has_track_total_hits(body)
        hint = (
            ""
            if track
            else " Add \"track_total_hits\": true to the body to get an exact count."
        )
        notices.append(
            f"[TOTAL COUNT TRUNCATED] hits.total.relation is \"gte\", so the reported "
            f"value {value} is a lower bound, not the real total. OpenSearch stops "
            f"counting at {TOTAL_HITS_CAP} by default.{hint}"
        )

    if isinstance(value, int) and value > 0:
        notices.extend(_aggregation_notices(parsed, value, body))

    return notices


def _has_track_total_hits(body: Any) -> bool:
    return isinstance(body, dict) and "track_total_hits" in body


def _aggregation_notices(parsed: dict[str, Any], total: int, body: Any) -> list[str]:
    """Report the gap between aggregation buckets and the documents in scope.

    A terms aggregation only counts documents that have a value for the field.
    When the bucket sum is far below the scope, the field is sparsely populated
    — which is exactly how a decoder gap becomes visible. Formatting that
    difference away would hide the most useful signal in the response.
    """
    notices: list[str] = []
    aggs = parsed.get("aggregations")
    if not isinstance(aggs, dict):
        return notices

    fields = _agg_field_map(body)

    for name, buckets, other, scope in _walk_bucket_aggs(aggs, total):
        # An aggregation over an empty scope is empty by definition, not by fault.
        # A filter agg that matched nothing is the common case here.
        if scope <= 0:
            continue

        field = fields.get(name)
        on_field = f" on field {field!r}" if field else ""

        if not buckets:
            notices.append(
                f"[EMPTY AGGREGATION] Aggregation {name!r}{on_field} produced 0 "
                f"buckets while {scope} documents were in scope. The field is "
                f"mapped but holds no value in any of them." + _shadow_hint(field)
            )
            continue

        bucket_sum = sum(
            b.get("doc_count", 0)
            for b in buckets
            if isinstance(b, dict) and isinstance(b.get("doc_count"), int)
        )
        covered = bucket_sum + other
        if covered < scope:
            missing = scope - covered
            pct = (covered / scope) * 100
            cause = (
                "truncated by the agg 'size' parameter and/or absent from documents"
                if other > 0
                else "absent from those documents (no value for the field)"
            )
            notices.append(
                f"[PARTIAL AGGREGATION COVERAGE] Aggregation {name!r}{on_field} "
                f"accounts for {covered} of {scope} documents in scope "
                f"({pct:.1f}%). {missing} documents are unrepresented: the field "
                f"is {cause}. sum_other_doc_count={other}. Do not read the "
                f"buckets as a breakdown of the full result set."
            )

    return notices


# --------------------------------------------------------------------------- #
# Engine tester sessions
# --------------------------------------------------------------------------- #


def tester_sessions(payload: Any) -> list[dict[str, Any]]:
    """Pull the `sessions` list out of a TableGet_Response, tolerating anything else."""
    if not isinstance(payload, dict):
        return []
    sessions = payload.get("sessions")
    if not isinstance(sessions, list):
        return []
    return [s for s in sessions if isinstance(s, dict)]


def session_state(session: dict[str, Any]) -> str:
    """Normalise `entry_status` to a State name.

    Protobuf JSON emits enum values by name, but a build that serialises them as
    integers would otherwise print a bare '1' where the caller needs to read
    'DISABLED' — the one value that explains a failing logtest.
    """
    raw = session.get("entry_status")
    if isinstance(raw, bool):
        return str(raw)
    if isinstance(raw, int):
        return TESTER_SESSION_STATES.get(raw, f"UNKNOWN({raw})")
    if isinstance(raw, str) and raw.strip():
        return raw.strip().upper()
    return "?"


def tester_notices(payload: Any) -> list[str]:
    """Explain a tester table that is present but cannot serve a logtest call.

    Same rule as everywhere else here: an empty list and a disabled session are
    both HTTP 200, and both are the answer to "why does logtest say the
    environment does not exist" — so neither may be rendered as plain success.
    """
    notices: list[str] = []

    if not isinstance(payload, dict):
        notices.append(
            "[NON-JSON RESPONSE] The engine returned a body that is not a JSON object."
        )
        return notices

    error = payload.get("error")
    status = payload.get("status")
    reported = str(error).strip() if isinstance(error, str) and error.strip() else ""
    status_is_error = isinstance(status, str) and status.strip().upper() not in {
        "OK",
        "RETURN_STATUS_OK",
    }

    if reported or status_is_error:
        # ReturnStatus is reported verbatim: the enum's numbering was not
        # verifiable, so the value is quoted rather than translated.
        detail = f": {reported}" if reported else ""
        notices.append(
            f"[TESTER ERROR] The engine answered HTTP 200 but reported status "
            f"{status!r} for the session table{detail}. The list below, if any, is "
            f"not a reliable inventory of the existing environments."
        )
        return notices

    sessions = tester_sessions(payload)
    if not sessions:
        notices.append(
            "[NO TESTER SESSIONS] The engine returned an empty session list. No test "
            "environment is provisioned, so every `logtest` call fails with \"The "
            "'<space>' environment does not exist\" regardless of the space named. "
            "Sessions are created when a policy is imported through the Content "
            "Manager API; import one rather than creating a session by hand."
        )
        return notices

    for session in sessions:
        if session_state(session) != "DISABLED":
            continue
        name = session.get("name")
        namespace = session.get("namespaceId")
        scope = f" in namespace {namespace!r}" if isinstance(namespace, str) else ""
        notices.append(
            f"[SESSION DISABLED] Session {name!r}{scope} exists but its entry_status "
            f"is DISABLED. The tester will not run events against it, so "
            f"`logtest` with space={name!r} fails the same way it does for an "
            f"environment that was never created. An existing name in this table is "
            f"not by itself proof that the space is usable."
        )

    return notices


def render(
    notices: list[str],
    response: Response,
    *,
    summary: str | None = None,
    footer: str | None = None,
    include_body: bool = True,
) -> str:
    """Assemble the final tool output: notices first, raw payload verbatim after.

    `summary` is a rendering placed above the raw payload, never instead of it —
    a table is easier to read than protobuf-shaped JSON, but it is an addition,
    and the caller still gets the untouched body underneath.

    `include_body=False` withholds the payload (an error body can echo the raw
    query and is opaque to the anonymization walker; the fail-closed reading
    serves the notices and a marker, not the body). The caller's audit log still
    carries the raw render separately.
    """
    parts: list[str] = []
    if notices:
        parts.append(PREAMBLE_HEADER)
        parts.extend(f"- {n}" for n in notices)
        parts.append("")
    if summary is not None:
        parts.append(summary)
        parts.append("")
    parts.append(f"{RAW_HEADER} (HTTP {response.status_code})")
    if include_body:
        parts.append(response.pretty())
    else:
        parts.append(
            "[BODY WITHHELD] The response body was withheld by the anonymization "
            "layer: an indexer error/shard-failure body can echo the raw query "
            "values. The masked exchange is recorded in llm_prompts.log."
        )
    if footer:
        parts.append("")
        parts.append(footer)
    return "\n".join(parts)
