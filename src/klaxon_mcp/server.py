# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Klaxon MCP: an MCP server exposing Wazuh 5.x through eight tools.

Wazuh 5 collapsed the separate 4.x data models into one: every event lands under
wazuh-events-v5-*, every detection result under wazuh-findings-v5-*, and the WCS
schema is global and enforced at decoder build time. A generic search tool
therefore covers events, findings and states at once, which is why this server
has six generic tools instead of one per domain — and why the sixth,
`tester_sessions`, is about the engine itself rather than about a data domain.

Two convenience tools sit on top of those six. `findings_overview` freezes the
findings aggregation every report repeats; `field_coverage` measures how much of
the data each field actually carries. Both exist because writing those queries
by hand is the step a small local model gets wrong, not because they reach
anything `search` and `schema` cannot. Both answer in tables rather than raw
JSON, and both put the request they issued in the footer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import coverage, diagnostics, gdpr, overview
from .anonymization import AggSpec, Anonymizer, parse_agg_fields
from .clients import (
    EngineClient,
    IndexerClient,
    ManagerClient,
    Response,
    TransportError,
)
from .config import Config, ConfigError
from .constants import (
    CATEGORIES,
    DETECTORS_BASE,
    DETECTORS_SEARCH,
    FINDINGS_LEVEL_FIELD,
    FINDINGS_PATTERN,
    LOGTEST_ENDPOINT,
    LOGTEST_SPACES,
    OVERVIEW_TOP_MAX,
    SHADOWED_NAMESPACES,
    SUGGESTED_PATTERNS,
    TESTER_TABLE_GET,
    TIME_FIELD,
    TRACE_LEVELS,
)
from .fields import (
    FieldInfo,
    count_documents,
    fetch_field_caps,
    fetch_field_mappings,
    probe_population,
    sample_source,
)
from .validation import (
    ValidationError,
    validate_detector_id,
    validate_index,
    validate_manager_path,
    validate_prefix,
)

mcp: MCPServer = MCPServer(
    "klaxon-mcp",
    instructions=(
        "Query a Wazuh 5.x deployment. Wazuh 5 stores all events in the "
        "datastream pattern wazuh-events-v5-* and all detection findings in "
        "wazuh-findings-v5-*; wazuh-alerts-* is a Wazuh 4.x name and does not "
        "exist here. Detection runs in the indexer via the OpenSearch Security "
        "Analytics plugin, so there are no Engine rules and no alert levels.\n\n"
        "Start with the `schema` tool before writing aggregations: many fields "
        "are mapped but never populated, and aggregating on one of those returns "
        "empty buckets with no error.\n\n"
        "For the standard findings breakdown — severity, agents, rule titles, "
        "categories — call `findings_overview` instead of writing that "
        "aggregation by hand. It is the same query every report needs, already "
        "written, and it prints the full severity scale including the levels "
        "that did not occur.\n\n"
        "To judge normalisation quality, use `field_coverage` rather than "
        "`schema`: it measures each field inside a time window as well as over "
        "the whole datastream. Those two numbers routinely differ by a lot, "
        "because a datastream spans decoder generations — quote the window "
        "figure for the pipeline as it runs now."
    ),
)

_config: Config | None = None
_indexer: IndexerClient | None = None
_manager: ManagerClient | None = None
_engine: EngineClient | None = None
_anonymizer: Anonymizer | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        try:
            _config = Config.from_env()
        except ConfigError as exc:
            raise ToolError(str(exc)) from exc
    return _config


def get_anonymizer() -> Anonymizer:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = Anonymizer(get_config().anonymization)
    return _anonymizer


def get_indexer() -> IndexerClient:
    global _indexer
    if _indexer is None:
        _indexer = IndexerClient(get_config())
    return _indexer


def get_manager() -> ManagerClient:
    global _manager
    if _manager is None:
        _manager = ManagerClient(get_config())
    return _manager


def get_engine() -> EngineClient:
    global _engine
    if _engine is None:
        _engine = EngineClient(get_config())
    return _engine


def _safe_prefix(prefix: str | None) -> str | None:
    """Normalise an optional field-name prefix, and guard it before it reaches a URL.

    Empty and whitespace-only collapse to None, which means "every field". The
    validation is not optional politeness: the prefix is interpolated into the
    _mapping/field/ path, so an unguarded one addresses any endpoint on the
    indexer. See validate_prefix().
    """
    if prefix is None:
        return None
    stripped = prefix.strip()
    if not stripped:
        return None
    try:
        return validate_prefix(stripped)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc


def _parse_body(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError as exc:
        raise ToolError(
            f"body is not valid JSON: {exc}. Pass the OpenSearch query DSL as a "
            "JSON string, e.g. '{\"size\":0,\"track_total_hits\":true,"
            '"query":{"range":{"@timestamp":{"gte":"now-24h"}}}}\''
        ) from exc


def _cap_size(body: Any, limit: int) -> str | None:
    """Lower an oversized `size` in the body in place; return a notice if it did.

    Applied before the query goes out, so the response the caller sees is the
    response to the capped request rather than a truncated rendering of a bigger
    one — the raw payload underneath the diagnostics block stays exactly what the
    indexer said.

    An absent `size` is left alone: the OpenSearch default of 10 is harmless.
    `"size": 0` is the normal shape of an aggregation-only query and must survive
    untouched, which it does — it is below any positive limit.
    """
    if limit <= 0 or not isinstance(body, dict):
        return None

    requested = body.get("size")
    # bool is an int subclass; "size": true is malformed anyway, so leave it to
    # the indexer to reject rather than silently rewriting it to a number.
    if not isinstance(requested, int) or isinstance(requested, bool):
        return None
    if requested <= limit:
        return None

    body["size"] = limit
    return diagnostics.size_capped_notice(requested, limit)


# --------------------------------------------------------------------------- #
# The anonymization guard
# --------------------------------------------------------------------------- #


def _render(
    tool: str,
    notices: list[str],
    response: Response,
    *,
    summary: str | None = None,
    footer: str | None = None,
    agg_map: dict[str, AggSpec] | None = None,
) -> str:
    """diagnostics.render plus the anonymization layer when it is active.

    The raw render is computed first — that is what the audit log's RAW line
    records when RAW logging is enabled. The response body is then masked
    structurally, the whole rendered output gets the text-level pass, and
    `finish` verifies and either returns the masked output or blocks it.
    """
    raw = diagnostics.render(notices, response, summary=summary, footer=footer)
    anon = get_anonymizer()
    if not anon.active:
        return raw
    masked_response = anon.mask_response(response, agg_map=agg_map)
    if masked_response is not response:
        masked = diagnostics.render(
            notices, masked_response, summary=summary, footer=footer
        )
    else:
        masked = raw
    return anon.finish(tool, raw, anon.mask_text(masked))


def _guarded_text(tool: str, text: str) -> str:
    """Run a plain rendered string through the anonymization layer."""
    anon = get_anonymizer()
    if not anon.active:
        return text
    return anon.finish(tool, text, anon.mask_text(text))


# --------------------------------------------------------------------------- #
# 1. search
# --------------------------------------------------------------------------- #


@mcp.tool()
async def search(index: str, body: str) -> str:
    """Run an OpenSearch query DSL request against a Wazuh 5 index pattern.

    Returns the raw JSON response, including `aggregations`, preceded by a
    diagnostics block when the result needs interpretation (zero hits, a
    truncated total, or an aggregation that covers only part of the result set).

    Common patterns:
      - wazuh-events-v5-*            all events
      - wazuh-findings-v5-*          all detection findings
      - wazuh-events-v5-<category>*  one of: access-management, applications,
        cloud-services, network-activity, other, security, system-activity,
        unclassified

    These are datastreams. Always query the wildcard pattern, never a backing
    index such as .ds-wazuh-events-v5-network-activity-000001.

    The time field is `@timestamp`. There is no `timestamp` field in Wazuh 5.
    Set "track_total_hits": true whenever you need an exact count; without it
    OpenSearch stops counting at 10000.

    A "size" larger than WAZUH_SEARCH_MAX_SIZE (default 100) is lowered to that
    limit before the query is sent, and the diagnostics block says so. Use
    "size": 0 with aggregations to count without pulling documents.

    When anonymization is enabled and KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS
    is on, aggregation bucket keys for masked fields (terms, multi_terms,
    composite) are replaced with the same deterministic tokens as the `_source`
    pass — so aggregation keys and hits stay aligned for the same entity.

    Args:
        index: Index or datastream pattern, e.g. "wazuh-events-v5-network-activity*".
        body: OpenSearch query DSL as a JSON string.
    """
    try:
        safe_index = validate_index(index)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    parsed_body = _parse_body(body)

    notices: list[str] = []
    capped = _cap_size(parsed_body, get_config().search_max_size)
    if capped:
        notices.append(capped)

    try:
        response = await get_indexer().post(f"/{safe_index}/_search", body=parsed_body)
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    notices.extend(diagnostics.search_notices(safe_index, parsed_body, response))
    if get_config().gdpr.check_on_search:
        sensitive = gdpr.scan_hits(response.json(), get_config().gdpr.custom_patterns)
        if sensitive:
            masking = "active" if get_anonymizer().active else "inactive"
            notices.append(
                f"[GDPR] The response carries {len(sensitive)} DSGVO-relevant "
                f"field(s) in its hits: {', '.join(sensitive)}. Masking is "
                f"{masking}. Run the `gdpr_check` tool to review and extend "
                f"the anonymization list."
            )
    # Aggregation-key masking (opt-in): map agg name -> source fields from the
    # forwarded request so the response walker can tokenise bucket keys with the
    # same tokens the `_source` pass produces.
    anon = get_anonymizer()
    agg_map = (
        parse_agg_fields(parsed_body)
        if anon.active and anon.config.mask_aggregation_keys
        else None
    )
    return _render("search", notices, response, agg_map=agg_map)


# --------------------------------------------------------------------------- #
# 2. schema
# --------------------------------------------------------------------------- #


def _shadow_hint(prefix: str | None) -> str | None:
    """Suggest the populated namespace when a shadowed one yields nothing."""
    if not prefix:
        return None
    for shadowed, populated in SHADOWED_NAMESPACES.items():
        if prefix.startswith(shadowed):
            replacement = populated + prefix[len(shadowed) :]
            return (
                f"The prefix {prefix!r} sits in a namespace that is mapped but not "
                f"populated in Wazuh 5. Retry with prefix {replacement!r}, which is "
                f"the branch the engine actually writes."
            )
    if not prefix.startswith("wazuh."):
        return (
            f"No populated field matched {prefix!r}. Wazuh 5 writes most of its own "
            f"metadata under the 'wazuh.' namespace; try prefix "
            f"{'wazuh.' + prefix!r} before concluding the data is missing."
        )
    return None


def _render_fields(rows: list[FieldInfo], probed: bool) -> str:
    if not rows:
        return "(no fields)"
    name_w = max(len(r.name) for r in rows)
    type_w = max(len(r.type_label) for r in rows)
    header = f"{'FIELD'.ljust(name_w)}  {'TYPE'.ljust(type_w)}"
    header += "  DOCS_WITH_VALUE" if probed else ""
    lines = [header, "-" * len(header)]
    for r in rows:
        line = f"{r.name.ljust(name_w)}  {r.type_label.ljust(type_w)}"
        if probed:
            line += f"  {r.doc_count if r.doc_count is not None else '?'}"
        lines.append(line)
    return "\n".join(lines)


@mcp.tool()
async def schema(
    index: str,
    prefix: str | None = None,
    only_populated: bool = True,
) -> str:
    """List the fields of a Wazuh 5 index and how many documents actually fill them.

    Use this before writing any aggregation. The Wazuh 5 engine schema defines
    2351 fields, and a mapped field is not necessarily a populated one: `agent.id`
    and `wazuh.agent.id` are both mapped as keyword, but only `wazuh.agent.id`
    ever carries a value. Aggregating on the wrong one returns zero buckets and
    HTTP 200 — no error at all. With only_populated=true this tool reports the
    document count per field, which makes that distinction visible.

    Namespace sizes in the engine schema: wazuh=492, threat=444, process=391,
    file=144, tls=77, host=57, observer=53, dll=46, user=46, client=35,
    destination=35, server=35.

    Args:
        index: Index or datastream pattern, e.g. "wazuh-events-v5-network-activity*".
        prefix: Restrict to a field namespace, e.g. "wazuh." or "source.".
            Strongly recommended — an unfiltered listing over 2351 fields is capped.
        only_populated: When true (default), issue a second pass with exists
            aggregations and return only fields holding a value in at least one
            document.
    """
    try:
        safe_index = validate_index(index)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    prefix = _safe_prefix(prefix)

    config = get_config()
    client = get_indexer()

    try:
        caps = await fetch_field_caps(client, safe_index, prefix)
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    notices: list[str] = []

    if not caps.ok:
        notices.append(
            f"[HTTP {caps.response.status_code}] _field_caps failed for {safe_index!r}. "
            "The unmodified error body is below."
        )
        parsed = caps.response.json()
        if isinstance(parsed, dict):
            err = parsed.get("error")
            if isinstance(err, dict) and err.get("type") == "index_not_found_exception":
                notices.append(
                    f"[INDEX NOT FOUND] Nothing matches {safe_index!r}. "
                    f"Valid starting points: {', '.join(SUGGESTED_PATTERNS)}."
                )
        return _render("schema", notices, caps.response)

    mapped = caps.fields
    truncated = False

    if not mapped:
        scope = f"prefix {prefix!r}" if prefix else "this index"
        notices.append(
            f"[NO MAPPED FIELDS] _field_caps returned no field matching {scope} "
            f"in {safe_index!r}. The namespace does not exist in the mapping at all, "
            f"so querying or aggregating on it returns empty results with no error."
        )
        hint = _shadow_hint(prefix)
        if hint:
            notices.append(f"[HINT] {hint}")
        return _schema_output(safe_index, prefix, notices, "(no fields)", 0, 0, False)

    if not only_populated:
        if prefix is None and len(mapped) > config.schema_field_limit:
            truncated = True
            notices.append(
                f"[TRUNCATED] {len(mapped)} fields are mapped; showing the first "
                f"{config.schema_field_limit} in alphabetical order. An unfiltered "
                f"listing of the full schema is not usable output — pass a `prefix` "
                f"(e.g. 'wazuh.', 'source.', 'threat.') to narrow it, or "
                f"only_populated=true to drop the unused ones."
            )
            mapped = mapped[: config.schema_field_limit]
        notices.append(
            "[MAPPED ONLY] only_populated=false: these fields exist in the mapping. "
            "This says nothing about whether any document fills them."
        )
        body = _render_fields(mapped, probed=False)
        return _schema_output(
            safe_index, prefix, notices, body, len(caps.fields), None, truncated
        )

    # only_populated=true: second pass with exists aggregations.
    try:
        counts, failures = await probe_population(
            client, safe_index, mapped, batch_size=config.schema_probe_batch
        )
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    for failed in failures:
        notices.append(
            f"[PROBE FAILED] An exists-aggregation batch returned HTTP "
            f"{failed.status_code}; some fields could not be checked and are "
            f"omitted. Body: {failed.text[:300]}"
        )

    populated: list[FieldInfo] = []
    for info in mapped:
        count = counts.get(info.name, 0)
        if count > 0:
            info.doc_count = count
            populated.append(info)

    populated.sort(key=lambda f: (-(f.doc_count or 0), f.name))

    if not populated:
        scope = f"prefix {prefix!r}" if prefix else "this index"
        notices.append(
            f"[MAPPED BUT UNPOPULATED] {len(mapped)} field(s) matching {scope} exist "
            f"in the mapping, but not one of them holds a value in any document of "
            f"{safe_index!r}. Querying or aggregating on them returns empty results "
            f"with HTTP 200 and no error."
        )
        hint = _shadow_hint(prefix)
        if hint:
            notices.append(f"[HINT] {hint}")
        body = "(no populated fields)\n\nMapped but empty:\n" + _render_fields(
            mapped, probed=False
        )
        return _schema_output(
            safe_index, prefix, notices, body, len(caps.fields), 0, truncated
        )

    empty_count = len(mapped) - len(populated)
    if empty_count:
        notices.append(
            f"[FILTERED] {empty_count} of {len(mapped)} mapped field(s) hold no value "
            f"in any document and are omitted. Pass only_populated=false to see them."
        )

    body = _render_fields(populated, probed=True)
    return _schema_output(
        safe_index, prefix, notices, body, len(caps.fields), len(populated), truncated
    )


def _schema_output(
    index: str,
    prefix: str | None,
    notices: list[str],
    body: str,
    mapped_total: int,
    populated_total: int | None,
    truncated: bool,
) -> str:
    parts: list[str] = []
    if notices:
        parts.append(diagnostics.PREAMBLE_HEADER)
        parts.extend(f"- {n}" for n in notices)
        parts.append("")
    parts.append(f"index:            {index}")
    parts.append(f"prefix:           {prefix or '* (all)'}")
    parts.append(f"mapped fields:    {mapped_total}")
    if populated_total is not None:
        parts.append(f"populated fields: {populated_total}")
    if truncated:
        parts.append("listing:          TRUNCATED")
    parts.append("")
    parts.append(body)
    return _guarded_text("schema", "\n".join(parts))


# --------------------------------------------------------------------------- #
# 3. logtest
# --------------------------------------------------------------------------- #


@mcp.tool()
async def logtest(
    event: str,
    location: str,
    queue: int = 49,
    space: str | None = None,
    trace_level: str | None = None,
    integration: str | None = None,
) -> str:
    """Run a raw log line through the Wazuh 5 decoder chain and return the result.

    Calls the Content Manager plugin on the indexer. The response shows which
    decoders matched and what the normalised WCS document looks like, which is
    the way to find out why a field is empty in the index.

    Args:
        event: The raw log line to decode.
        location: Log source path, e.g. "/var/ossec/logs/opnsense_syslog.log".
        queue: Queue id of the originating source. Defaults to 49.
        space: One of test, custom, standard — logtest supports no others. Custom
            decoders live in "custom"; "standard" carries only the shipped ruleset.
            A valid name does not guarantee the environment is provisioned — use
            the `tester_sessions` tool to see which ones exist and are enabled.
        trace_level: One of NONE, ASSET_ONLY, ALL. Defaults to ASSET_ONLY, which
            is the level that reveals the matched decoder chain. NONE returns the
            normalised event only; ALL adds per-asset trace detail.
        integration: Integration name for the detection phase. Without it the
            plugin normalises the event and reports detection as "skipped".
    """
    config = get_config()

    # Name the source in the error: an invalid default comes from the
    # environment, not from the call, and reporting the argument would send the
    # caller looking in the wrong place.
    level_from_env = trace_level is None
    level = (
        config.logtest_default_trace_level if level_from_env else trace_level or ""
    ).strip().upper()
    if level not in TRACE_LEVELS:
        source = "WAZUH_LOGTEST_TRACE_LEVEL" if level_from_env else "trace_level"
        raise ToolError(
            f"{source} must be one of {', '.join(TRACE_LEVELS)} (got {level!r}). "
            f"ASSET_ONLY is the level that shows the decoder chain."
        )

    space_from_env = space is None
    resolved_space = (
        config.logtest_default_space if space is None else space
    ).strip().lower()
    if resolved_space not in LOGTEST_SPACES:
        source = "WAZUH_LOGTEST_SPACE" if space_from_env else "space"
        raise ToolError(
            f"{source} must be one of {', '.join(LOGTEST_SPACES)} (got {resolved_space!r}). "
            f"The Content Manager rejects every other space for logtest."
        )

    payload: dict[str, Any] = {
        "space": resolved_space,
        "queue": queue,
        "location": location,
        "trace_level": level,
        "event": event,
    }
    if integration is not None:
        payload["integration"] = integration

    try:
        response = await get_indexer().post(LOGTEST_ENDPOINT, body=payload)
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    notices: list[str] = []
    if not response.ok:
        notices.append(
            f"[HTTP {response.status_code}] logtest was rejected. The unmodified "
            f"response body is below."
        )
    else:
        notices.extend(_logtest_notices(response))

    footer = f"request: POST {LOGTEST_ENDPOINT}\n{json.dumps(payload, indent=2)}"
    if get_anonymizer().active:
        # The footer echoes the raw event line; mask it so the request recap
        # carries no more personal data than the (already masked) response.
        masked_payload = dict(payload)
        masked_payload["event"] = get_anonymizer().mask_text(payload["event"])
        footer = (
            f"request: POST {LOGTEST_ENDPOINT}\n"
            f"{json.dumps(masked_payload, indent=2)}"
        )

    return _render("logtest", notices, response, footer=footer)


def _logtest_notices(response: Response) -> list[str]:
    """Surface phase failures that the plugin reports inside an HTTP 200.

    The Content Manager answers a rejected request with HTTP 200 and an error
    nested under message.normalization — exactly the shape of silent failure
    this server exists to prevent.
    """
    notices: list[str] = []
    parsed = response.json()
    if not isinstance(parsed, dict):
        return notices

    message = parsed.get("message")
    if not isinstance(message, dict):
        return notices

    for phase in ("normalization", "detection"):
        node = message.get(phase)
        if not isinstance(node, dict):
            continue
        status = node.get("status")
        if status == "error":
            err = node.get("error")
            detail = ""
            message_text = ""
            if isinstance(err, dict):
                message_text = str(err.get("message", ""))
                detail = f": {message_text} ({err.get('code', '')})"
            notices.append(
                f"[LOGTEST {phase.upper()} FAILED] The plugin returned HTTP 200 but "
                f"the {phase} phase reported an error{detail}. No decoder chain was "
                f"produced."
            )
            if "environment does not exist" in message_text:
                notices.append(
                    "[HINT] The space name is accepted but that environment is not "
                    "provisioned on this instance. Run the `tester_sessions` tool to "
                    "see which environments exist and whether they are enabled — a "
                    "session that exists but is DISABLED fails exactly like a missing "
                    "one. Then retry with a name from that list; space='test' is the "
                    "usual fallback, because it normally carries the custom decoders "
                    "while 'standard' holds only the shipped ruleset."
                )
        elif status == "skipped":
            notices.append(
                f"[LOGTEST {phase.upper()} SKIPPED] reason: {node.get('reason')!r}. "
                f"Pass the `integration` argument to run the detection phase."
            )
    return notices


# --------------------------------------------------------------------------- #
# 4. manager
# --------------------------------------------------------------------------- #


@mcp.tool()
async def manager(path: str, params: dict[str, Any] | None = None) -> str:
    """Issue a GET against the Wazuh manager API and return the response unchanged.

    A deliberately thin passthrough. The manager API is the volatile half of
    Wazuh 5 and breaks further at GA (/var/ossec moves to /var/wazuh-manager,
    clustering becomes the default, agent id 000 disappears), so this tool adds
    no interpretation on top of it.

    Non-2xx responses are returned as they are, status code included. In Wazuh 5
    several 4.x endpoints are gone and their 404 is the correct answer, not a
    failure to hide:
      - /rules                 404, the Engine has no RULE content type any more
      - /manager/logs          404
      - /manager/stats/remoted 404
    Verified working: /agents, /syscollector/{agent_id}/...
    Changed response schemas: /cluster/healthcheck (no `enabled` field),
    /cluster/nodes (no `node_type` field).

    The `security` root is restricted to /security/users/me and
    /security/users/me/policies — enough to tell RBAC filtering apart from an
    empty deployment when /agents returns less than expected, without
    enumerating the deployment's accounts, roles and policies through a tool
    meant for agent and event data.

    Args:
        path: Manager API path, e.g. "/agents".
        params: Optional query parameters.
    """
    try:
        safe_path = validate_manager_path(path)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    try:
        response = await get_manager().get(safe_path, params=params)
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    notices: list[str] = []
    if response.status_code == 404:
        notices.append(
            f"[HTTP 404] {safe_path!r} does not exist on this manager. In Wazuh 5 "
            f"this is frequently the correct answer rather than an error — several "
            f"4.x endpoints were removed outright. Reported as-is; the response "
            f"body below is unmodified."
        )
    elif not response.ok:
        notices.append(
            f"[HTTP {response.status_code}] Returned unmodified from the manager API."
        )

    return _render("manager", notices, response, footer=f"request: GET {safe_path}")


# --------------------------------------------------------------------------- #
# 5. detectors
# --------------------------------------------------------------------------- #


@mcp.tool()
async def detectors(
    action: str = "list",
    detector_id: str | None = None,
    size: int = 50,
) -> str:
    """List or fetch OpenSearch Security Analytics detectors.

    Detection in Wazuh 5 lives in the indexer, not in the Engine. These
    detectors are what produces the documents in wazuh-findings-v5-*.

    The plugin exposes no list-all endpoint, so `list` is implemented as
    POST /_plugins/_security_analytics/detectors/_search with match_all. Detector
    documents are nested under the `detector` path, which matters if you search
    them by name.

    Args:
        action: "list" for all detectors, "get" for a single one by id.
        detector_id: Required when action is "get".
        size: Maximum number of detectors to return for "list". Defaults to 50.
    """
    normalised = action.strip().lower()
    if normalised not in {"list", "get"}:
        raise ToolError(f"action must be 'list' or 'get', got {action!r}")

    client = get_indexer()

    if normalised == "get":
        if not detector_id:
            raise ToolError("detector_id is required when action is 'get'")
        try:
            safe_id = validate_detector_id(detector_id)
        except ValidationError as exc:
            raise ToolError(str(exc)) from exc

        try:
            response = await client.get(f"{DETECTORS_BASE}/{safe_id}")
        except TransportError as exc:
            raise ToolError(str(exc)) from exc

        notices: list[str] = []
        if response.status_code == 404:
            notices.append(
                f"[HTTP 404] No detector with id {safe_id!r}. Use action='list' to "
                f"see the ids that exist."
            )
        elif not response.ok:
            notices.append(
                f"[HTTP {response.status_code}] Returned unmodified from the "
                f"Security Analytics plugin."
            )
        return _render(
            "detectors", notices, response, footer=f"request: GET {DETECTORS_BASE}/{safe_id}"
        )

    if size < 1:
        raise ToolError("size must be at least 1")

    body: dict[str, Any] = {"size": size, "query": {"match_all": {}}}
    try:
        response = await client.post(DETECTORS_SEARCH, body=body)
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    notices = []
    if not response.ok:
        notices.append(
            f"[HTTP {response.status_code}] The Security Analytics plugin rejected "
            f"the detector search. If this is a 404, the plugin may not be "
            f"installed on this indexer. Body returned unmodified below."
        )
    else:
        parsed = response.json()
        if isinstance(parsed, dict):
            hits = parsed.get("hits")
            if isinstance(hits, dict):
                inner = hits.get("hits")
                if isinstance(inner, list) and not inner:
                    notices.append(
                        "[NO DETECTORS] The plugin responded successfully with an "
                        "empty detector list. No detectors are configured, so "
                        "wazuh-findings-v5-* will not be receiving new documents."
                    )
                elif isinstance(inner, list) and len(inner) == size:
                    notices.append(
                        f"[POSSIBLY TRUNCATED] Exactly {size} detectors returned, "
                        f"which equals the requested size. There may be more; "
                        f"raise `size` to check."
                    )

    return _render(
        "detectors", notices, response, footer=f"request: POST {DETECTORS_SEARCH}"
    )


# --------------------------------------------------------------------------- #
# 6. tester_sessions
# --------------------------------------------------------------------------- #


def _render_sessions(sessions: list[dict[str, Any]]) -> str:
    """Tabulate the session list. Unset fields print as '-', never as invented values."""
    if not sessions:
        return "(no sessions)"

    def cell(session: dict[str, Any], key: str) -> str:
        value = session.get(key)
        return "-" if value is None else str(value)

    rows: list[tuple[str, ...]] = [
        (
            cell(s, "name"),
            cell(s, "namespaceId"),
            diagnostics.session_state(s),
            cell(s, "lifetime"),
            cell(s, "last_use"),
        )
        for s in sessions
    ]
    header = ("NAME", "NAMESPACE", "STATUS", "LIFETIME", "LAST_USE")
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header))]
    def line(cells: tuple[str, ...]) -> str:
        return "  ".join(c.ljust(w) for c, w in zip(cells, widths)).rstrip()

    body = [line(header), *(line(row) for row in rows)]
    lines = [body[0], "-" * max(len(row) for row in body), *body[1:]]

    descriptions = [
        f"  {s.get('name')}: {s['description']}"
        for s in sessions
        if isinstance(s.get("description"), str) and s["description"].strip()
    ]
    if descriptions:
        lines.append("")
        lines.append("descriptions:")
        lines.extend(descriptions)
    return "\n".join(lines)


@mcp.tool()
async def tester_sessions(action: str = "list") -> str:
    """List the Wazuh 5 engine test sessions — the environments `logtest` can use.

    `logtest` answers a call naming an environment that does not exist with
    HTTP 200 and "The '<space>' environment does not exist" buried in the body.
    This tool is how to find out which environments there actually are, and
    whether they are enabled.

    Calls POST /_internal/tester/table/get on the engine's internal HTTP API.
    That server runs inside the *manager* container on its own port, so it needs
    WAZUH_ENGINE_URL — the indexer and manager URLs do not reach it.

    Read-only by design. The engine also exposes session/post, session/delete and
    session/reload; none of them are wired up here. Sessions are recreated on
    every policy import through the Content Manager API, so a hand-made session
    disappears at the next import — a create tool would only invite a workaround
    that does not hold.

    Args:
        action: Only "list" is supported.
    """
    normalised = action.strip().lower()
    if normalised != "list":
        raise ToolError(
            f"action must be 'list', got {action!r}. This tool is read-only: the "
            f"engine's session/post, session/delete and session/reload routes are "
            f"deliberately not exposed, because a policy import through the Content "
            f"Manager API recreates the sessions and discards manual ones."
        )

    try:
        response = await get_engine().post(TESTER_TABLE_GET)
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    if response.status_code in (401, 403):
        return _render(
            "tester_sessions",
            [
                f"[HTTP {response.status_code}] The engine's internal API refused the "
                f"request. Klaxon sends no credentials to it: the auth scheme of "
                f"/_internal/* is not documented and was not verifiable, so nothing "
                f"is guessed at here. If this build fronts the engine with an "
                f"authenticating proxy, put Klaxon behind it or point "
                f"WAZUH_ENGINE_URL at an endpoint that does not require the token."
            ],
            response,
            footer=f"request: POST {TESTER_TABLE_GET}",
        )

    if response.status_code == 404:
        return _render(
            "tester_sessions",
            [
                f"[HTTP 404] {TESTER_TABLE_GET} does not exist at "
                f"{get_config().engine_url!r}. Either this build predates the route, "
                f"or WAZUH_ENGINE_URL points at the indexer or the manager API rather "
                f"than at the engine's own HTTP server inside the manager container."
            ],
            response,
            footer=f"request: POST {TESTER_TABLE_GET}",
        )

    if not response.ok:
        return _render(
            "tester_sessions",
            [
                f"[HTTP {response.status_code}] The engine rejected the session table "
                f"request. The unmodified body is below."
            ],
            response,
            footer=f"request: POST {TESTER_TABLE_GET}",
        )

    parsed = response.json()
    notices = diagnostics.tester_notices(parsed)
    sessions = diagnostics.tester_sessions(parsed)

    return _render(
        "tester_sessions",
        notices,
        response,
        summary=f"sessions: {len(sessions)}\n\n{_render_sessions(sessions)}",
        footer=f"request: POST {TESTER_TABLE_GET}",
    )


# --------------------------------------------------------------------------- #
# 7. findings_overview
# --------------------------------------------------------------------------- #


def _positive(name: str, value: int, maximum: int | None = None) -> int:
    """Reject a non-positive or oversized count before a query is built from it."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ToolError(
            f"{name} must be a positive integer (got {value!r}). "
            f"There is no 'all' or 'unlimited' value: 0 and negative numbers "
            f"produce a query that cannot answer the question."
        )
    if maximum is not None and value > maximum:
        raise ToolError(
            f"{name} must not exceed {maximum} (got {value}). A terms aggregation "
            f"builds a priority queue per shard, so an unbounded size is a load "
            f"question rather than a formatting one."
        )
    return value


def _summary_output(
    notices: list[str], head: str, body: str, footer: str | None = None
) -> str:
    """Assemble the tool output: diagnostics first, tables after, no raw JSON.

    Used by the two convenience tools, the only ones that do not append the
    unmodified response. Their whole purpose is to replace a page of aggregation
    JSON with something a small local model can read back without re-deriving it
    — so what went out on the wire goes in the footer instead, and `search`
    remains available for anyone who wants the payload itself.
    """
    parts: list[str] = []
    if notices:
        parts.append(diagnostics.PREAMBLE_HEADER)
        parts.extend(f"- {n}" for n in notices)
        parts.append("")
    parts.append(head)
    parts.append("")
    parts.append(body)
    if footer:
        parts.append("")
        parts.append(footer)
    return "\n".join(parts)


def _guarded_summary(
    tool: str, notices: list[str], head: str, body: str, footer: str | None = None
) -> str:
    """_summary_output plus the anonymization layer.

    The structured pass for the convenience tools happens before rendering (the
    caller masks the parsed Overview), so the raw string is already free of
    field-level PII; the text pass and the residual scan still run here.
    """
    raw = _summary_output(notices, head, body, footer)
    anon = get_anonymizer()
    if not anon.active:
        return raw
    return anon.finish(tool, raw, anon.mask_text(raw))


@mcp.tool()
async def findings_overview(
    hours: int = 24,
    top_agents: int = 10,
    top_titles: int = 10,
) -> str:
    """Summarise wazuh-findings-v5-* by severity, agent, rule title and category.

    A frozen query for the breakdown every report starts with, so that producing
    it needs no valid OpenSearch query DSL. `search` still covers everything
    else; this tool only removes the need to hand-write the one aggregation that
    recurs.

    Severity is `wazuh.rule.level`, a keyword holding a *string* — critical,
    high, medium, low, informational — not a Wazuh 4.x numeric level. The whole
    scale is printed in canonical order with an explicit 0 for the levels that
    did not occur, because a terms aggregation returns only the values it found:
    a missing `critical` bucket cannot distinguish "none occurred" from "never
    populated". Any value outside the scale is listed as well and marked
    UNKNOWN. Before aggregating, the tool probes whether `wazuh.rule.level` is
    populated at all and says so instead of printing a table of zeros.

    Output is a compact set of tables, not raw JSON. The request that produced
    them is in the footer if you want to re-run or extend it via `search`.

    Args:
        hours: Size of the time window ending now, in hours. Default 24.
        top_agents: How many agents to list, by finding count. Default 10.
        top_titles: How many rule titles to list. Default 10.
    """
    hours = _positive("hours", hours)
    top_agents = _positive("top_agents", top_agents, OVERVIEW_TOP_MAX)
    top_titles = _positive("top_titles", top_titles, OVERVIEW_TOP_MAX)

    client = get_indexer()
    notices: list[str] = []

    # Same exists-probe as the `schema` tool, for the same reason: a field that
    # is mapped but never populated aggregates to zero buckets with HTTP 200.
    # Rendering the scale with zeros everywhere would then look like a clean
    # "nothing found" — the exact silent-wrong-answer this server exists against.
    try:
        counts, failures = await probe_population(
            client,
            FINDINGS_PATTERN,
            [FieldInfo(name=FINDINGS_LEVEL_FIELD)],
            batch_size=1,
        )
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    level_docs = counts.get(FINDINGS_LEVEL_FIELD)

    if failures:
        failed = failures[0]
        notices.append(
            f"[PROBE FAILED] The exists check on {FINDINGS_LEVEL_FIELD!r} returned "
            f"HTTP {failed.status_code}, so it is unverified whether the field is "
            f"populated at all. A severity table of zeros below may mean an empty "
            f"field rather than an empty window. Body: {failed.text[:300]}"
        )
    elif level_docs == 0:
        notices.append(
            f"[SEVERITY FIELD UNPOPULATED] {FINDINGS_LEVEL_FIELD!r} is mapped in "
            f"{FINDINGS_PATTERN} but holds no value in a single document of the "
            f"index — not in this window, not anywhere. No severity breakdown is "
            f"produced: a table reading 0 for every level would state that no "
            f"critical findings occurred, when what actually happened is that "
            f"nothing was ever measured. Aggregating on this field returns empty "
            f"buckets with HTTP 200 and no error, so the emptiness is invisible "
            f"from the response alone."
        )
        notices.append(
            f"[NEXT STEP] Run `schema` with index={FINDINGS_PATTERN!r} and "
            f"prefix='wazuh.rule.' to see which fields under that branch do carry "
            f"data, and `detectors` to check that anything is writing findings at "
            f"all."
        )
        return _guarded_summary(
            "findings_overview",
            notices,
            overview.header(FINDINGS_PATTERN, hours, None, 0),
            "(no severity breakdown — the field is empty index-wide)",
        )

    body = overview.build_query(hours, top_agents, top_titles)
    path = f"/{FINDINGS_PATTERN}/_search"
    footer = f"request: POST {path}\n{json.dumps(body, indent=2)}"

    try:
        response = await client.post(path, body=body)
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    if not response.ok:
        notices.append(
            f"[HTTP {response.status_code}] The indexer rejected the overview query "
            f"against {FINDINGS_PATTERN!r}. No summary was produced; the unmodified "
            f"error body is below."
        )
        return _render("findings_overview", notices, response, footer=footer)

    result = overview.parse(response.json())
    if get_anonymizer().active:
        result = get_anonymizer().mask_overview(result)

    if result.total == 0:
        scope = (
            f" The field is populated in {level_docs} document(s) index-wide, so "
            f"this is an empty window rather than an empty field."
            if level_docs
            else ""
        )
        notices.append(
            f"[EMPTY WINDOW] No finding in {FINDINGS_PATTERN} carries an "
            f"{TIME_FIELD} within the last {hours}h. Nothing is summarised below — "
            f"the tables are omitted rather than shown as zeros, because zero "
            f"findings in a window is not the same statement as zero findings per "
            f"severity level.{scope} Widen `hours` before concluding the deployment "
            f"is quiet."
        )
        return _guarded_summary(
            "findings_overview",
            notices,
            overview.header(FINDINGS_PATTERN, hours, 0, level_docs),
            f"(no findings in the last {hours}h)",
            footer,
        )

    notices.extend(diagnostics.search_notices(FINDINGS_PATTERN, body, response))
    notices.extend(overview.overview_notices(result, hours))
    notices.append(overview.SCALE_NOTICE)

    return _guarded_summary(
        "findings_overview",
        notices,
        overview.header(FINDINGS_PATTERN, hours, result.total, level_docs),
        overview.render(result),
        footer,
    )


# --------------------------------------------------------------------------- #
# 8. field_coverage
# --------------------------------------------------------------------------- #


@mcp.tool()
async def field_coverage(
    index: str,
    prefix: str | None = None,
    hours: int = 24,
    min_docs: int = 0,
) -> str:
    """Measure what share of the documents actually carries a value per field.

    The normalisation-quality measurement, callable without query DSL. For each
    mapped field it reports the document count and coverage inside a time window
    *and* across the whole datastream, because those are different questions:

        event.action, wazuh-events-v5-network-activity*
          whole datastream (10,238,381 docs)     8.1%
          last 24 hours       (348,247 docs)    71.0%
          last 12 hours                        100.0%

    A decoder fix had landed hours earlier. All three numbers are correct. The
    window describes the pipeline as it runs now, the datastream describes the
    stored history — quote the one you mean. When they differ by more than 20
    percentage points the diagnostics block says so explicitly, because that gap
    is the signature of a change in normalisation inside the datastream.

    Fields with 0% coverage are listed, never filtered: mapped-but-never-
    populated is the `agent.id` trap and the most important result this
    measurement produces.

    Coverage is three-valued — populated, not populated, not measurable. An
    exists aggregation returns 0 for a field the mapping declares "index": false
    no matter what the documents hold, so the mapping is read first and such
    fields are reported as not measurable, with dashes, never as 0%. Verified:
    event.original in wazuh-events-v5-network-activity* is index:false and
    doc_values:false, matches 0 of 10,243,389 documents, and carries the
    complete raw log line in _source of every document sampled. For those fields
    the tool samples _source and reports in how many of the sampled documents
    the key is present — evidence rather than a coverage figure.

    Cost scales with the field count — the schema has 2351 fields — so the
    listing is capped at WAZUH_SCHEMA_FIELD_LIMIT (default 200) and the cap is
    reported. Pass a `prefix` to measure a namespace instead of a truncation.

    Args:
        index: Index or datastream pattern, e.g. "wazuh-events-v5-network-activity*".
        prefix: Restrict to a field namespace, e.g. "source." or "wazuh.".
        hours: Size of the time window ending now, in hours. Default 24.
        min_docs: Hide fields below this document count in the window. Default 0,
            which hides nothing. Any higher value removes the 0% fields — the
            ones worth looking at — so the output says how many it dropped.
    """
    try:
        safe_index = validate_index(index)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    prefix = _safe_prefix(prefix)

    hours = _positive("hours", hours)
    if isinstance(min_docs, bool) or not isinstance(min_docs, int) or min_docs < 0:
        raise ToolError(
            f"min_docs must be zero or a positive integer (got {min_docs!r}). "
            f"Zero is the default and hides nothing."
        )

    config = get_config()
    client = get_indexer()
    notices: list[str] = []

    # 1. What is mapped.
    try:
        caps = await fetch_field_caps(client, safe_index, prefix)
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    if not caps.ok:
        notices.append(
            f"[HTTP {caps.response.status_code}] _field_caps failed for "
            f"{safe_index!r}; no coverage was measured. The unmodified error body "
            f"is below."
        )
        parsed = caps.response.json()
        if isinstance(parsed, dict):
            err = parsed.get("error")
            if isinstance(err, dict) and err.get("type") == "index_not_found_exception":
                notices.append(
                    f"[INDEX NOT FOUND] Nothing matches {safe_index!r}. "
                    f"Valid starting points: {', '.join(SUGGESTED_PATTERNS)}."
                )
        return _render("field_coverage", notices, caps.response)

    mapped = caps.fields
    if not mapped:
        scope = f"prefix {prefix!r}" if prefix else "this index"
        notices.append(
            f"[NO MAPPED FIELDS] _field_caps returned no field matching {scope} in "
            f"{safe_index!r}. Nothing can be measured: the namespace does not exist "
            f"in the mapping at all, so querying it returns empty results with no "
            f"error."
        )
        hint = _shadow_hint(prefix)
        if hint:
            notices.append(f"[HINT] {hint}")
        return _guarded_summary(
            "field_coverage",
            notices,
            coverage.header(safe_index, prefix, hours, None, None, 0, 0),
            "(no fields to measure)",
        )

    measured = mapped
    if len(mapped) > config.schema_field_limit:
        measured = mapped[: config.schema_field_limit]
        notices.append(
            f"[TRUNCATED] {len(mapped)} field(s) match; the first "
            f"{config.schema_field_limit} in alphabetical order were measured and "
            f"the remaining {len(mapped) - config.schema_field_limit} were not "
            f"probed at all. They are absent from the table below, which is not "
            f"the same as reading 0% — nothing is known about them. Narrow the run "
            f"with `prefix`, or raise WAZUH_SCHEMA_FIELD_LIMIT (currently "
            f"{config.schema_field_limit})."
        )

    # 2. The two denominators. Both exact: a lower bound as a denominator would
    #    inflate every percentage in the table.
    window = coverage.window_query(hours)
    try:
        grand_total, total_response = await count_documents(client, safe_index)
        window_total, window_response = await count_documents(
            client, safe_index, window
        )
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    for label, response in (("datastream", total_response), ("window", window_response)):
        if not response.ok:
            notices.append(
                f"[HTTP {response.status_code}] Counting the documents in the "
                f"{label} failed, so there is no denominator and no coverage can be "
                f"computed. The unmodified error body is below."
            )
            return _render("field_coverage", notices, response)

    if grand_total is None or window_total is None:
        notices.append(
            "[NO DOCUMENT COUNT] The indexer answered the count query without a "
            "readable hits.total. No percentage is reported rather than one "
            "derived from a guessed denominator."
        )
        return _guarded_summary(
            "field_coverage",
            notices,
            coverage.header(
                safe_index, prefix, hours, window_total, grand_total, len(mapped), 0
            ),
            "(no coverage measured)",
        )

    if grand_total == 0:
        notices.append(
            f"[NO DOCUMENTS] {safe_index!r} matches {len(mapped)} mapped field(s) "
            f"but holds no document at all, in this window or any other. Coverage "
            f"is undefined without documents to divide by — this is not a table of "
            f"0% fields, it is an empty index. Check the pattern before concluding "
            f"the normalisation is broken."
        )
        return _guarded_summary(
            "field_coverage",
            notices,
            coverage.header(safe_index, prefix, hours, 0, 0, len(mapped), 0),
            "(no documents in scope)",
        )

    window_measured = window_total > 0
    if not window_measured:
        notices.append(
            f"[EMPTY WINDOW] No document in {safe_index!r} carries a {TIME_FIELD} "
            f"within the last {hours}h, while {grand_total} document(s) exist in the "
            f"datastream. Window coverage is left blank ({coverage.MISSING}) rather "
            f"than computed against zero, and the STATUS column falls back to the "
            f"datastream figure. Widen `hours` to measure the current pipeline."
        )

    # 3. What the mapping lets exists answer at all. This has to happen before
    #    the probe, not after: an unindexed field returns 0 from every exists
    #    aggregation regardless of what the documents hold, and a 0 that reaches
    #    the table as "never populated" is a false report, not a cautious one.
    try:
        mappings, mapping_response = await fetch_field_mappings(
            client, safe_index, prefix
        )
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    if not mapping_response.ok:
        notices.append(
            f"[MAPPING CHECK FAILED] GET the field mappings for {safe_index!r} "
            f"returned HTTP {mapping_response.status_code}, so it is unverified "
            f"whether every field below can be measured at all. A field declared "
            f"index:false answers every exists aggregation with 0 whatever it "
            f"contains — any 0% row below may be that rather than an empty field. "
            f"Body: {mapping_response.text[:300]}"
        )

    unmeasurable = [
        info.name
        for info in measured
        if info.name in mappings and mappings[info.name].unindexed
    ]
    probeable = [info for info in measured if info.name not in set(unmeasurable)]

    # 4. The probes. Same exists-aggregation batching as `schema`, run twice:
    #    once over the datastream, once inside the window. Fields exists cannot
    #    answer for are left out — probing them would only manufacture zeros.
    try:
        total_counts, total_failures = await probe_population(
            client, safe_index, probeable, batch_size=config.schema_probe_batch
        )
        window_counts: dict[str, int] = {}
        window_failures: list[Response] = []
        if window_measured:
            window_counts, window_failures = await probe_population(
                client,
                safe_index,
                probeable,
                batch_size=config.schema_probe_batch,
                query=window,
            )
    except TransportError as exc:
        raise ToolError(str(exc)) from exc

    for label, failures in (("datastream", total_failures), ("window", window_failures)):
        for failed in failures:
            notices.append(
                f"[PROBE FAILED] An exists-aggregation batch over the {label} "
                f"returned HTTP {failed.status_code}. The fields in that batch read "
                f"0 in the table below without having been measured — treat those "
                f"rows as unknown, not as empty. Body: {failed.text[:300]}"
            )

    # 5. What _source says about the fields exists could not reach. One request,
    #    a handful of documents: not a coverage figure, and never rendered as
    #    one — but it is the difference between "not measurable" and "not
    #    measurable, and the value is in every document sampled".
    samples: dict[str, int] = {}
    sample_size: int | None = None
    if unmeasurable:
        try:
            samples, sampled, sample_response = await sample_source(
                client,
                safe_index,
                unmeasurable,
                size=coverage.SOURCE_SAMPLE_SIZE,
                query=window if window_measured else None,
            )
        except TransportError as exc:
            raise ToolError(str(exc)) from exc

        if sample_response.ok:
            sample_size = sampled
        else:
            notices.append(
                f"[SOURCE SAMPLE FAILED] Reading _source for the "
                f"{len(unmeasurable)} unmeasurable field(s) returned HTTP "
                f"{sample_response.status_code}. They are still reported as not "
                f"measurable; there is simply no evidence either way about what "
                f"they contain."
            )

    # 6. Rows.
    rows = coverage.sort_rows(
        coverage.build_rows(
            measured,
            window_counts,
            total_counts,
            window_total,
            grand_total,
            mappings=mappings,
            samples=samples,
            sample_size=sample_size,
        )
    )
    kept, hidden = coverage.apply_min_docs(rows, min_docs)

    if hidden:
        never = sum(1 for r in hidden if r.category == coverage.CATEGORY_NEVER)
        notices.append(
            f"[MIN_DOCS FILTER] min_docs={min_docs} removed {len(hidden)} of "
            f"{len(rows)} field(s) from the table, {never} of them at 0% coverage. "
            f"A mapped field that is never populated is the finding this tool is "
            f"for; set min_docs=0 to see them."
        )

    # The unmeasurable notice comes first: it decides how every 0% below is to
    # be read.
    for notice in (
        coverage.unmeasurable_notice(kept),
        coverage.partially_indexed_notice(kept),
        coverage.drift_notice(kept, hours),
        coverage.never_populated_notice(kept),
    ):
        if notice:
            notices.append(notice)

    # How the numbers were obtained, so the measurement can be audited or
    # repeated through `search` without reverse-engineering it from the table.
    passes = 2 if window_measured else 1
    batches = -(-len(probeable) // config.schema_probe_batch) * passes
    searches = batches + 2 + (1 if unmeasurable else 0)
    footer = (
        f"requests: GET /{safe_index}/_field_caps?fields={prefix or ''}*\n"
        f"          GET /{safe_index}/_mapping/field/{prefix or ''}*\n"
        f"          POST /{safe_index}/_search  x{searches}  "
        f"(2 document counts, {batches} exists batch(es) of up to "
        f"{config.schema_probe_batch} field(s) over {passes} pass(es)"
        + (", 1 _source sample)" if unmeasurable else ")")
    )

    return _guarded_summary(
        "field_coverage",
        notices,
        coverage.header(
            safe_index,
            prefix,
            hours,
            window_total,
            grand_total,
            len(mapped),
            len(measured),
        ),
        coverage.render(kept, window_measured),
        footer,
    )


# --------------------------------------------------------------------------- #
# 9. gdpr_check
# --------------------------------------------------------------------------- #


@mcp.tool()
async def gdpr_check(
    index: str,
    prefix: str | None = None,
    sample_docs: int | None = None,
    apply: bool = False,
    exclude: list[str] | None = None,
    as_json: bool = False,
) -> str:
    """Run the DSGVO plausibility check on an index: find sensitive fields.

    Reads the index mappings, samples a few documents, and classifies the
    fields by three heuristics in decreasing certainty: custom rules from
    config.yaml (`gdpr_checker.custom_patterns`), field-name patterns
    (`source.ip`, `user.name`, `host.hostname`, `user.email`, ...), and sampled
    values (an actual value like `192.168.1.100` reveals an IP even when the
    field name does not).

    Priorities: IPs, usernames and e-mails are directly personal (high);
    hostnames and agent ids are indirectly personal (medium); free-text fields
    that embed personal data are flagged as such. Fields already in the
    anonymization `mask_fields` are reported as covered, not re-suggested.

    With `apply=true` the suggested fields are merged into
    `anonymization.mask_fields` of config.yaml (KLAXON_CONFIG), the action is
    appended to `gdpr_check.log`, and `gdpr_compliance_report.json` is
    written. The change takes effect for the running server on restart unless
    KLAXON_ANONYMIZATION_MASK_FIELDS is set, which always overrides the file.
    `apply=false` (default) is a dry run: suggestions only, nothing changed.

    Args:
        index: Index or datastream pattern, e.g. "wazuh-events-v5-*".
        prefix: Restrict to a field namespace, e.g. "user." or "source.".
        sample_docs: Documents to sample for content analysis. Defaults to
            KLAXON_GDPR_SAMPLE_SIZE (10). 0 disables sampling.
        apply: When true, merge the suggested fields into config.yaml and log.
        exclude: Field names to skip (e.g. internal fields without GDPR
            relevance).
        as_json: When true, return a machine-readable JSON report instead of
            the table.
    """
    try:
        safe_index = validate_index(index)
    except ValidationError as exc:
        raise ToolError(str(exc)) from exc

    prefix = _safe_prefix(prefix)
    config = get_config()
    gdpr_cfg = config.gdpr
    sample = sample_docs if sample_docs is not None else gdpr_cfg.sample_size
    excluded = set(exclude or ())
    already = set(get_anonymizer().config.mask_fields)

    try:
        result = await gdpr.run_check(
            get_indexer(),
            safe_index,
            prefix,
            sample,
            gdpr_cfg.custom_patterns,
            already,
            excluded,
        )
    except RuntimeError as exc:
        raise ToolError(str(exc)) from exc

    if result.caps_failed is not None:
        notices = [
            f"[HTTP {result.caps_failed.status_code}] _field_caps failed for "
            f"{safe_index!r}; no DSGVO analysis was produced. The unmodified "
            f"error body is below."
        ]
        return _render("gdpr_check", notices, result.caps_failed)

    if as_json:
        return gdpr.render_json(result)

    head = (
        "=== DSGVO PLAUSIBILITY CHECK ===\n"
        f"index:    {safe_index}\n"
        f"checked:  {result.mapped_total} mapped field(s)"
        f" (sampled {result.sample_size} document(s) for content)"
    )
    body = gdpr.render_table(result.sensitive)

    summary = []
    total = len(result.sensitive)
    covered = sum(1 for f in result.sensitive if f.already_configured)
    to_add = result.new_fields
    summary.append(f"{total} DSGVO-relevant field(s) found; {covered} already "
                   f"in mask_fields; {len(to_add)} to add.")
    if to_add:
        summary.append(
            f"env equivalent: {gdpr.env_hint(to_add)}"
        )
    if apply and to_add:
        changed, merged, warning = gdpr.update_mask_fields(
            gdpr_cfg.config_file, to_add
        )
        gdpr_log = gdpr.GdprLog(gdpr_cfg.log_path)
        if changed:
            joined = ", ".join(to_add)
            gdpr_log.write(
                f'Felder "{joined}" zur Anonymisierungsliste hinzugefügt '
                f"(index {safe_index})."
            )
        if warning:
            gdpr_log.write(f"Warnung: {warning}")
        gdpr.write_compliance_report(
            gdpr_cfg.report_path,
            {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "index": safe_index,
                "checked_fields": result.mapped_total,
                "sensitive_fields_found": total,
                "anonymization_updated": changed,
                "fields_added": to_add if changed else [],
            },
        )
        if changed:
            summary.append(
                f"config.yaml updated ({gdpr_cfg.config_file}): "
                f"{len(merged)} field(s) in mask_fields. The running server "
                f"picks this up on restart."
            )
        else:
            summary.append("nothing added (all fields already configured or rejected).")
    elif apply and not to_add:
        summary.append("nothing to add — every sensitive field is already covered.")
    else:
        summary.append(
            "dry run (apply=false): nothing changed. Re-run with apply=true to "
            "merge the fields into config.yaml."
        )

    parts = [head, "", body, "", "--- summary ---"]
    parts.extend(f"- {line}" for line in summary)
    return _guarded_text("gdpr_check", "\n".join(parts))


# --------------------------------------------------------------------------- #

# Categories are parameter values, never separate tools. Exposed as a resource
# so a client can enumerate them without a round trip to the cluster.
@mcp.resource("wazuh://categories")
def categories() -> str:
    """The eight fixed Wazuh 5 integration categories."""
    return "\n".join(CATEGORIES)


def run() -> None:
    """Serve on the transport configured in the environment (stdio by default)."""
    from .config import TransportConfig
    from .transport import serve

    serve(mcp, TransportConfig.from_env())
