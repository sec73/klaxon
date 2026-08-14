# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Facts about Wazuh 5.x that are anchored in engine source, not guessed.

Every constant here is traceable to a file in github.com/wazuh/wazuh at tag
v5.0.0-beta3. Do not "modernise" these values without re-checking the source.
"""

from __future__ import annotations

from typing import Final

# src/engine/source/cmstore/interface/cmstore/categories.hpp:25-32
# Fixed set, not extensible. These are parameter values, never separate tools.
# The eighth entry is the UNCLASSIFIED_CATEGORY constant declared on line 17,
# not a string literal inside the array — grepping the array range for
# "unclassified" finds nothing.
CATEGORIES: Final[tuple[str, ...]] = (
    "access-management",
    "applications",
    "cloud-services",
    "network-activity",
    "other",
    "security",
    "system-activity",
    "unclassified",
)

# src/engine/source/builder/src/builders/stage/indexerOutput.cpp:59 enforces
#   ^wazuh-events-v5-(?:[a-z0-9.-]+|\$\{[^}]+\})*$
# wazuh-alerts-* does not exist in Wazuh 5; it is an explicit FAILURE test case
# in indexerOutput_test.cpp:63.
EVENTS_PATTERN: Final[str] = "wazuh-events-v5-*"
FINDINGS_PATTERN: Final[str] = "wazuh-findings-v5-*"

SUGGESTED_PATTERNS: Final[tuple[str, ...]] = (EVENTS_PATTERN, FINDINGS_PATTERN)

# The time field. Wazuh 4.x wrote `timestamp`; 5.x has `@timestamp` and nothing
# else. A query on the 4.x name matches nothing and reports HTTP 200.
TIME_FIELD: Final[str] = "@timestamp"

# --------------------------------------------------------------------------- #
# The findings data model, as measured on a live 5.0.0-beta4 instance.
#
# Every field the `findings_overview` tool aggregates on is named here and
# nowhere else, so a schema change is a one-line edit rather than a hunt through
# query bodies and rendering code.
#
# All of them sit under `wazuh.`. The `rule.` branch is mapped and empty in
# wazuh-findings-v5-*, exactly like `agent.` — see SHADOWED_NAMESPACES.
# --------------------------------------------------------------------------- #
FINDINGS_LEVEL_FIELD: Final[str] = "wazuh.rule.level"
FINDINGS_TITLE_FIELD: Final[str] = "wazuh.rule.title"
FINDINGS_TACTIC_FIELD: Final[str] = "wazuh.rule.mitre.tactic.name"
FINDINGS_AGENT_NAME_FIELD: Final[str] = "wazuh.agent.name"
FINDINGS_AGENT_ID_FIELD: Final[str] = "wazuh.agent.id"
FINDINGS_CATEGORY_FIELD: Final[str] = "wazuh.integration.category"

# `wazuh.rule.level` is a keyword holding a *string*, not a 4.x numeric level.
# Canonical order, most severe first. Observed on the measured instance:
# medium, low, informational — `critical` and `high` did not occur, which is
# precisely why the tool prints the whole scale with explicit zeros instead of
# the buckets the aggregation happened to return.
SEVERITY_SCALE: Final[tuple[str, ...]] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)

# Deliberately far above len(SEVERITY_SCALE): a value outside the scale must
# land in a bucket of its own rather than be dropped into sum_other_doc_count,
# where it would be invisible.
SEVERITY_TERMS_SIZE: Final[int] = 50

# Eight categories exist (CATEGORIES); the extra room keeps an unexpected value
# out of sum_other_doc_count for the same reason.
CATEGORY_TERMS_SIZE: Final[int] = 25

# Upper bound for the top_agents / top_titles parameters of `findings_overview`.
# A terms aggregation is a per-shard priority queue; an unbounded `size` is a
# cluster-load question, not a formatting one.
OVERVIEW_TOP_MAX: Final[int] = 1000

# Index patterns that belonged to Wazuh 4.x. Searching these against a 5.x
# cluster returns an empty hit list rather than an error, which is precisely how
# both predecessor servers silently reported "no alerts" forever.
LEGACY_4X_PATTERNS: Final[tuple[str, ...]] = (
    "wazuh-alerts",
    "wazuh-archives",
    "wazuh-monitoring",
    "wazuh-statistics",
)

# The single most important trap in the 5.x schema: both `agent.*` and
# `wazuh.agent.*` are mapped as keyword, but only the wazuh.* branch is
# populated. A terms aggregation on agent.id returns empty buckets with no
# error. Mapping from the shadowed namespace to the populated one.
SHADOWED_NAMESPACES: Final[dict[str, str]] = {
    "agent.": "wazuh.agent.",
}

# Indexer plugin endpoints.
LOGTEST_ENDPOINT: Final[str] = "/_plugins/_content_manager/logtest"

# Verified against a running 5.0 instance: an invalid value is answered with
# "Invalid trace level: <x>. Only support: NONE, ASSET_ONLY, ALL".
# ASSET_ONLY is what makes the matched decoder chain visible.
TRACE_LEVELS: Final[tuple[str, ...]] = ("NONE", "ASSET_ONLY", "ALL")
DEFAULT_TRACE_LEVEL: Final[str] = "ASSET_ONLY"

# Also verified against a live instance: "Logtest is only supported for the
# 'test', 'custom' and 'standard' spaces." A name being valid does not mean the
# environment is provisioned — the plugin answers HTTP 200 with
# "The '<space>' environment does not exist." when it is not.
LOGTEST_SPACES: Final[tuple[str, ...]] = ("test", "custom", "standard")
DETECTORS_BASE: Final[str] = "/_plugins/_security_analytics/detectors"
DETECTORS_SEARCH: Final[str] = f"{DETECTORS_BASE}/_search"

# Manager API: JWT handshake.
MANAGER_AUTH_PATH: Final[str] = "/security/user/authenticate"

# src/engine/source/api/tester/include/api/tester/handlers.hpp:37-42 (v5.0.0-beta4)
# registers five tester routes, all POST:
#   /_internal/tester/session/post    create a session
#   /_internal/tester/session/delete  remove one
#   /_internal/tester/session/get     read one
#   /_internal/tester/session/reload  reload one
#   /_internal/tester/table/get       list them all
# Only the last is exposed. The four mutating routes are deliberately absent:
# api/cmcrud/src/handlers.cpp (`shouldPromote`) recreates the sessions on every
# policy import through the Content Manager API, so a hand-made session is gone
# after the next import. A tool for it would be an invitation to a workaround
# that does not survive the day.
#
# These live on the engine's own HTTP server inside the MANAGER container —
# a different host and port from KLAXON_INDEXER_URL and from the manager API.
TESTER_TABLE_GET: Final[str] = "/_internal/tester/table/get"

# src/engine/source/proto/src/tester.proto:8-13, enum State. Protobuf JSON
# serialises enums by name, so the wire form is normally the string; the numeric
# mapping is kept for builds that emit integers instead.
TESTER_SESSION_STATES: Final[dict[int, str]] = {
    0: "STATE_UNKNOWN",
    1: "DISABLED",
    2: "ENABLED",
}

# OpenSearch caps hits.total at 10000 unless track_total_hits is set.
TOTAL_HITS_CAP: Final[int] = 10_000
