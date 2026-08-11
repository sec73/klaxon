# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Input guards for every tool argument that reaches a request URL.

`search`/`schema`/`field_coverage` interpolate an index pattern, `manager`
interpolates a path, `detectors` interpolates an id, and `schema`/
`field_coverage` interpolate a field-name prefix. Those are the only places
where tool input reaches the URL, so all of them are validated here and
unit-tested independently of any live instance.

The prefix is the one that is easy to overlook, because it looks like a filter
rather than an address. It is not: it lands in the path of
GET /{index}/_mapping/field/{prefix}*, and httpx resolves "../" against the
base URL before the request goes out.
"""

from __future__ import annotations

import re
from typing import Final

MAX_INDEX_LENGTH: Final[int] = 255
MAX_MANAGER_PATH_LENGTH: Final[int] = 512
MAX_PREFIX_LENGTH: Final[int] = 255

# Only these characters may appear in an index pattern. Note the absence of "/",
# which is what stops a pattern from addressing a different endpoint, and the
# absence of uppercase, which OpenSearch rejects for index names anyway.
_INDEX_ALLOWED: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9._*,\-]+$")

# Tenant names flow into resource names, index patterns and filesystem paths;
# see validate_tenant(). Note the absence of '/', '*', ',', whitespace and '..'.
_TENANT_ALLOWED: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9._-]+$")

# Manager paths carry agent IDs, group names and node names.
_MANAGER_ALLOWED: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._/\-]+$")

# A field-name prefix. WCS field names are dotted snake_case, so the permitted
# set is narrow — but what matters is what is absent. No "/", which is what
# stops a prefix from addressing a different endpoint; no "?" or "#", either of
# which terminates the path and discards the "*" appended after it; and no "%",
# which would smuggle any of those back in percent-encoded. "@" is in the set
# for `@timestamp`, "*" because the mapping API takes field wildcards.
_PREFIX_ALLOWED: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.@*\-]+$")

# Top-level Manager API resources. This is an anti-traversal guard, not a
# feature restriction: /rules is deliberately present so that its 404 reaches
# the caller intact. A 404 on /rules is a correct and informative answer in
# Wazuh 5 — the Engine has no RULE content type any more.
MANAGER_PATH_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "agents",
        "active-response",
        "ciscat",
        "cluster",
        "decoders",
        "default",
        "events",
        "experimental",
        "groups",
        "lists",
        "manager",
        "mitre",
        "overview",
        "rootcheck",
        "rules",
        "sca",
        "security",  # only the paths in MANAGER_RESTRICTED_ROOTS; see below
        "syscheck",
        "syscollector",
        "tasks",
        "vulnerability",
    }
)

# Roots that are allowlisted for named paths only, rather than wholesale.
#
# `security` is here because the root covers two very different things. GET
# /security/users, /roles, /policies, /rules and /config enumerate the entire
# RBAC model and every API account of the deployment — reconnaissance material
# with no bearing on querying a SIEM, reachable from a tool whose stated job is
# agent and syscollector data. Under the blanket root it was exposed by
# inheritance rather than by decision.
#
# The self-introspection paths stay, because they answer a question this server
# exists to answer. When /agents returns fewer agents than the operator expects,
# RBAC filtering and an empty deployment look identical — HTTP 200 with a short
# list, no error. /security/users/me/policies is what distinguishes them, and it
# discloses nothing beyond the permissions of the credentials Klaxon was already
# configured with.
#
# The JWT handshake does not appear here and must not: POST
# /security/user/authenticate is issued by ManagerClient against
# MANAGER_AUTH_PATH directly, never through this validator, and the `manager`
# tool is GET-only regardless.
MANAGER_RESTRICTED_ROOTS: Final[dict[str, frozenset[str]]] = {
    "security": frozenset(
        {
            "/security/users/me",
            "/security/users/me/policies",
        }
    ),
}


class ValidationError(ValueError):
    """Raised when caller-supplied input fails a guard."""


def validate_tenant(tenant: str) -> str:
    """Validate a tenant name before it reaches resource names or paths.

    Tenants are interpolated into `klaxon-mask-<tenant>`,
    `klaxon-masked-<tenant>-v5-*`, `klaxon-masked-retention-<tenant>`, the
    sync-state doc id and the `tenants/<tenant>/` directory. An unguarded tenant
    (containing '/', '..', '*', ',', whitespace, ...) could escape a resource
    name, an index pattern or the tenants directory. The permitted set is what
    OpenSearch accepts in an index component: lowercase letters, digits, '.',
    '-' and '_'.

    Returns the tenant unchanged when valid; raises ValidationError otherwise.
    """
    if not isinstance(tenant, str):  # defensive: schema should prevent this
        raise ValidationError("tenant must be a string")

    stripped = tenant.strip()
    if not stripped:
        raise ValidationError("tenant must not be empty")

    if len(stripped) > 64:
        raise ValidationError(
            f"tenant exceeds 64 characters (got {len(stripped)})"
        )

    if not _TENANT_ALLOWED.match(stripped):
        raise ValidationError(
            "tenant contains disallowed characters; permitted set is "
            "[a-z0-9._-] (lowercase, no '/', no '*', no ',', no whitespace)"
        )

    if ".." in stripped:
        raise ValidationError("tenant must not contain '..'")

    return stripped


def validate_index(index: str) -> str:
    """Validate an index pattern for interpolation into an indexer URL.

    Rules: charset [a-z0-9._*,-] only, no "..", no leading "_" or "/" on any
    comma-separated component, max 255 characters.

    Returns the pattern unchanged when valid; raises ValidationError otherwise.
    """
    if not isinstance(index, str):  # defensive: schema should prevent this
        raise ValidationError("index must be a string")

    stripped = index.strip()
    if not stripped:
        raise ValidationError("index must not be empty")

    if len(stripped) > MAX_INDEX_LENGTH:
        raise ValidationError(
            f"index exceeds {MAX_INDEX_LENGTH} characters (got {len(stripped)})"
        )

    if not _INDEX_ALLOWED.match(stripped):
        raise ValidationError(
            "index contains disallowed characters; permitted set is "
            "[a-z0-9._*,-] (lowercase only, no '/')"
        )

    if ".." in stripped:
        raise ValidationError("index must not contain '..'")

    for part in stripped.split(","):
        if not part:
            raise ValidationError("index must not contain an empty comma-separated part")
        if part.startswith("_"):
            raise ValidationError(
                f"index component {part!r} must not start with '_' "
                "(reserved for API endpoints)"
            )

    return stripped


def validate_prefix(prefix: str) -> str:
    """Validate a field-name prefix for interpolation into an indexer URL.

    `schema` and `field_coverage` take this as a namespace filter, and it looks
    like one — but it is interpolated into the path of

        GET /{index}/_mapping/field/{prefix}*

    and httpx resolves dot segments against the base URL before sending. Left
    unguarded, prefix="../../../_cat/indices#" leaves the path as /_cat/indices:
    three levels up reaches the cluster root, and the "#" swallows the trailing
    "*". That turns a field listing into an arbitrary GET against the indexer
    with the configured credentials — /_cluster/settings, /_nodes,
    /_plugins/_security/api/internalusers — which is exactly the escape
    validate_index() exists to prevent, one argument over.

    Rules: charset [A-Za-z0-9_.@*-] only, no "..", max 255 characters.

    Returns the prefix unchanged when valid; raises ValidationError otherwise.
    """
    if not isinstance(prefix, str):  # defensive: schema should prevent this
        raise ValidationError("prefix must be a string")

    stripped = prefix.strip()
    if not stripped:
        raise ValidationError("prefix must not be empty; omit it to list every field")

    if len(stripped) > MAX_PREFIX_LENGTH:
        raise ValidationError(
            f"prefix exceeds {MAX_PREFIX_LENGTH} characters (got {len(stripped)})"
        )

    if not _PREFIX_ALLOWED.match(stripped):
        raise ValidationError(
            "prefix contains disallowed characters; permitted set is "
            "[A-Za-z0-9_.@*-]. A prefix names a field namespace such as 'wazuh.' "
            "or 'source.' — it is not a path and must not contain '/', '?' or '#'."
        )

    if ".." in stripped:
        raise ValidationError("prefix must not contain '..'")

    return stripped


def validate_manager_path(path: str) -> str:
    """Validate a Manager API path.

    Only the path is validated here; the caller is responsible for issuing GET
    and nothing else.
    """
    if not isinstance(path, str):  # defensive
        raise ValidationError("path must be a string")

    stripped = path.strip()
    if not stripped:
        raise ValidationError("path must not be empty")

    if not stripped.startswith("/"):
        stripped = "/" + stripped

    if len(stripped) > MAX_MANAGER_PATH_LENGTH:
        raise ValidationError(
            f"path exceeds {MAX_MANAGER_PATH_LENGTH} characters (got {len(stripped)})"
        )

    if "?" in stripped or "#" in stripped:
        raise ValidationError(
            "path must not contain a query string or fragment; use the 'params' argument"
        )

    if "//" in stripped:
        raise ValidationError("path must not contain '//'")

    if not _MANAGER_ALLOWED.match(stripped):
        raise ValidationError(
            "path contains disallowed characters; permitted set is [A-Za-z0-9._/-]"
        )

    segments = [s for s in stripped.split("/") if s]
    if not segments:
        raise ValidationError("path must name a resource, e.g. /agents")

    if any(seg == ".." for seg in segments):
        raise ValidationError("path must not contain '..'")

    root = segments[0]
    if root not in MANAGER_PATH_ALLOWLIST:
        allowed = ", ".join(sorted(MANAGER_PATH_ALLOWLIST))
        raise ValidationError(
            f"path root {root!r} is not in the allowlist. Permitted roots: {allowed}"
        )

    normalised = "/" + "/".join(segments)

    permitted = MANAGER_RESTRICTED_ROOTS.get(root)
    if permitted is not None and normalised not in permitted:
        paths = ", ".join(sorted(permitted))
        raise ValidationError(
            f"{normalised!r} is not reachable through this tool. The {root!r} root "
            f"is restricted to: {paths}. The rest of it — users, roles, policies, "
            f"rules, config — enumerates the deployment's RBAC model and API "
            f"accounts, which is not what this server is for. Read it with the "
            f"manager API directly if you need it."
        )

    return normalised


def validate_detector_id(detector_id: str) -> str:
    """Validate a Security Analytics detector id before URL interpolation."""
    if not isinstance(detector_id, str):  # defensive
        raise ValidationError("detector_id must be a string")

    stripped = detector_id.strip()
    if not stripped:
        raise ValidationError("detector_id must not be empty")

    if len(stripped) > 128:
        raise ValidationError("detector_id exceeds 128 characters")

    if not re.match(r"^[A-Za-z0-9_\-]+$", stripped):
        raise ValidationError(
            "detector_id contains disallowed characters; permitted set is [A-Za-z0-9_-]"
        )

    return stripped
