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

from typing import Any

from .clients import Response
from .constants import (
    LEGACY_4X_PATTERNS,
    SHADOWED_NAMESPACES,
    SUGGESTED_PATTERNS,
    TESTER_SESSION_STATES,
    TOTAL_HITS_CAP,
)

PREAMBLE_HEADER = "=== DIAGNOSTICS (added by Klaxon MCP; not part of the API response) ==="
RAW_HEADER = "=== RAW RESPONSE ==="

SEARCH_SIZE_ENV = "WAZUH_SEARCH_MAX_SIZE"


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
            f"against {index!r}. The unmodified error body is below."
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
) -> str:
    """Assemble the final tool output: notices first, raw payload verbatim after.

    `summary` is a rendering placed above the raw payload, never instead of it —
    a table is easier to read than protobuf-shaped JSON, but it is an addition,
    and the caller still gets the untouched body underneath.
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
    parts.append(response.pretty())
    if footer:
        parts.append("")
        parts.append(footer)
    return "\n".join(parts)
