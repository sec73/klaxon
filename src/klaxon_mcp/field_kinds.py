# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Field-name classification knowledge, shared by the response-layer anonymizer,
the GDPR checker and the default config.

Before this module existed the field tables lived in three places — the
anonymizer's `_FIELD_KIND`, the GDPR checker's `_NAME_PATTERNS` and the config
default mask list — maintained by hand and able to drift apart. This is the
single home for that knowledge.

The two vocabularies are deliberately separate: the anonymizer works in
placeholder families (IP/USER/HOST/AGENT), the GDPR checker in GDPR kinds
(IP_ADDRESS/USERNAME/...). They answer different questions and stay independent
tables here; `tenants/<tenant>/fields.yaml` remains the authority for a
tenant's mask list (see `klaxon masking generate`).
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------- #
# Response-layer placeholder families (used by anonymization)
# --------------------------------------------------------------------------- #

# Dotted field-name suffix -> placeholder family. The suffix match runs against
# the full dotted path, so "user.name" also covers "source.user.name". A
# configured mask field not listed here falls back to USER — masking it as a
# generic identifier is the safe reading.
FIELD_KIND: dict[str, str] = {
    ".ip": "IP",
    "user.name": "USER",
    "user.id": "USER",
    "source.user.name": "USER",
    "destination.user.name": "USER",
    "host.hostname": "HOST",
    "host.name": "HOST",
    "agent.name": "HOST",
    "wazuh.agent.name": "HOST",
    "related.hosts": "HOST",
    "agent.id": "AGENT",
    "wazuh.agent.id": "AGENT",
    "source.domain": "HOST",
    "destination.domain": "HOST",
    "url.domain": "HOST",
}


def field_kind(field: str) -> str:
    """The placeholder family for a configured mask field.

    Exact keys first (user.name), then the shortest matching dotted suffix
    (".ip" catches source.ip, destination.ip, related.ip, ...). Anything unknown
    falls back to USER — masking it as a generic identifier is the safe reading.
    """
    if field in FIELD_KIND:
        return FIELD_KIND[field]
    for suffix, kind in FIELD_KIND.items():
        if field.endswith(suffix):
            return kind
    return "USER"


# --------------------------------------------------------------------------- #
# GDPR field-name patterns (used by gdpr). Ordered: the first match wins, so
# the specific entries (user.name vs user.id) come before the generic ones
# that would swallow them. Kinds are the GDPR vocabulary, not placeholder
# families.
# --------------------------------------------------------------------------- #

NAME_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"(^|\.)user\.name$", "USERNAME", "high"),
    (r"(^|\.)username$", "USERNAME", "high"),
    (r"(^|\.)user\.id$", "USER_ID", "high"),
    (r"email", "EMAIL", "high"),
    (r"(^|\.)ip$", "IP_ADDRESS", "high"),
    (r"hostname", "HOSTNAME", "medium"),
    (r"(^|\.)host\.name$", "HOSTNAME", "medium"),
    (r"(^|\.)agent\.name$", "HOSTNAME", "medium"),
    (r"(^|\.)agent\.id$", "AGENT_ID", "medium"),
    (r"\.domain$", "DOMAIN", "medium"),
)

NAME_PATTERN_RES: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(pattern), kind, priority)
    for pattern, kind, priority in NAME_PATTERNS
)


def name_match(field: str) -> tuple[str, str] | None:
    """The (kind, priority) of the first GDPR name pattern that matches, if any."""
    for regex, kind, priority in NAME_PATTERN_RES:
        if regex.search(field):
            return kind, priority
    return None


# --------------------------------------------------------------------------- #
# Default anonymization mask list (used by config). The value under each field
# is replaced wholesale; the placeholder family is derived from the field name
# (see field_kind()). Every entry is dotted, so a suffix match also covers the
# nested position, e.g. "user.name" -> "source.user.name".
# --------------------------------------------------------------------------- #

DEFAULT_ANONYMIZATION_MASK_FIELDS: tuple[str, ...] = (
    "source.ip",
    "destination.ip",
    "client.ip",
    "server.ip",
    "related.ip",
    "source.domain",
    "destination.domain",
    "host.hostname",
    "host.name",
    "user.name",
    "user.id",
    "user.effective.name",
    "source.user.name",
    "destination.user.name",
    "wazuh.agent.name",
    "wazuh.agent.id",
    "agent.name",
    "agent.id",
)
