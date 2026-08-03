# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Guards on the tool arguments that reach a request URL."""

from __future__ import annotations

import httpx
import pytest

from klaxon_mcp.constants import MANAGER_AUTH_PATH
from klaxon_mcp.validation import (
    MANAGER_PATH_ALLOWLIST,
    MANAGER_RESTRICTED_ROOTS,
    ValidationError,
    validate_detector_id,
    validate_index,
    validate_manager_path,
    validate_prefix,
)


class TestValidateIndex:
    @pytest.mark.parametrize(
        "value",
        [
            "wazuh-events-v5-*",
            "wazuh-findings-v5-*",
            "wazuh-events-v5-network-activity*",
            "wazuh-events-v5-cloud-services-aws",
            "wazuh-events-v5-*,wazuh-findings-v5-*",
            ".ds-wazuh-events-v5-network-activity-000001",
            "a",
            "a" * 255,
        ],
    )
    def test_accepts_valid_patterns(self, value: str) -> None:
        assert validate_index(value) == value

    def test_strips_surrounding_whitespace(self) -> None:
        assert validate_index("  wazuh-events-v5-*  ") == "wazuh-events-v5-*"

    @pytest.mark.parametrize("value", ["", "   "])
    def test_rejects_empty(self, value: str) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_index(value)

    def test_rejects_over_length(self) -> None:
        with pytest.raises(ValidationError, match="exceeds 255"):
            validate_index("a" * 256)

    @pytest.mark.parametrize(
        "value",
        [
            "wazuh-events/_search",  # slash would re-target the endpoint
            "wazuh-events-v5-*/_mapping",
            "/wazuh-events-v5-*",
            "Wazuh-Events-V5-*",  # uppercase
            "wazuh events",  # space
            "wazuh-events-v5-*?pretty",
            "wazuh:events",
            "wazuh-events\n-v5",
            "wazuh-events%2f_search",
        ],
    )
    def test_rejects_disallowed_characters(self, value: str) -> None:
        with pytest.raises(ValidationError, match="disallowed characters"):
            validate_index(value)

    @pytest.mark.parametrize(
        "value",
        ["..", "wazuh..events", "..wazuh-events-v5-*", "wazuh-events-v5-*..*"],
    )
    def test_rejects_parent_traversal(self, value: str) -> None:
        with pytest.raises(ValidationError, match=r"must not contain '\.\.'"):
            validate_index(value)

    @pytest.mark.parametrize(
        "value", ["_search", "_all", "_cluster", "wazuh-events-v5-*,_search"]
    )
    def test_rejects_leading_underscore_component(self, value: str) -> None:
        """A leading underscore would address an API endpoint, not an index."""
        with pytest.raises(ValidationError, match="must not start with '_'"):
            validate_index(value)

    @pytest.mark.parametrize("value", ["wazuh-events-v5-*,", ",wazuh", "a,,b"])
    def test_rejects_empty_comma_component(self, value: str) -> None:
        with pytest.raises(ValidationError, match="empty comma-separated part"):
            validate_index(value)

    def test_legacy_4x_pattern_is_syntactically_valid(self) -> None:
        """wazuh-alerts-* is a legal index name; it is caught by diagnostics,
        not by the validator, because rejecting it here would be a lie about
        why it returns nothing."""
        assert validate_index("wazuh-alerts-*") == "wazuh-alerts-*"


class TestValidateManagerPath:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("/agents", "/agents"),
            ("agents", "/agents"),
            ("/agents/", "/agents"),
            ("/rules", "/rules"),
            ("/syscollector/001/packages", "/syscollector/001/packages"),
            ("/cluster/healthcheck", "/cluster/healthcheck"),
            ("/manager/stats/remoted", "/manager/stats/remoted"),
            ("  /agents  ", "/agents"),
        ],
    )
    def test_accepts_and_normalises(self, value: str, expected: str) -> None:
        assert validate_manager_path(value) == expected

    def test_rules_is_allowlisted_so_its_404_can_surface(self) -> None:
        """/rules must reach the manager: its 404 is the informative answer."""
        assert validate_manager_path("/rules") == "/rules"
        assert "rules" in MANAGER_PATH_ALLOWLIST

    @pytest.mark.parametrize("value", ["", "   ", "/"])
    def test_rejects_empty(self, value: str) -> None:
        with pytest.raises(ValidationError):
            validate_manager_path(value)

    @pytest.mark.parametrize(
        "value",
        [
            "/../etc/passwd",
            "/agents/../../secret",
            "/agents/..",
            "..",
        ],
    )
    def test_rejects_traversal(self, value: str) -> None:
        with pytest.raises(ValidationError):
            validate_manager_path(value)

    @pytest.mark.parametrize(
        "value", ["/agents//list", "//agents", "/agents//"]
    )
    def test_rejects_double_slash(self, value: str) -> None:
        with pytest.raises(ValidationError, match=r"must not contain '//'"):
            validate_manager_path(value)

    @pytest.mark.parametrize(
        "value", ["/agents?limit=1", "/agents#frag", "/agents?a=b&c=d"]
    )
    def test_rejects_inline_query_string(self, value: str) -> None:
        with pytest.raises(ValidationError, match="query string or fragment"):
            validate_manager_path(value)

    @pytest.mark.parametrize(
        "value",
        ["/etc/passwd", "/admin", "/unknown", "/Agents", "/_cat"],
    )
    def test_rejects_root_outside_allowlist(self, value: str) -> None:
        with pytest.raises(ValidationError, match="not in the allowlist"):
            validate_manager_path(value)

    @pytest.mark.parametrize(
        "value", ["/agents;ls", "/agents$(id)", "/agents ls", "/agents|cat"]
    )
    def test_rejects_disallowed_characters(self, value: str) -> None:
        with pytest.raises(ValidationError, match="disallowed characters"):
            validate_manager_path(value)

    def test_rejects_over_length(self) -> None:
        with pytest.raises(ValidationError, match="exceeds 512"):
            validate_manager_path("/agents/" + "a" * 600)


class TestSecurityRootIsRestricted:
    """The `security` root grants two very different things under one name.

    Self-introspection answers a question this server is built to answer — RBAC
    filtering and an empty deployment both look like HTTP 200 with a short list.
    Enumerating accounts, roles and policies answers a different one, and it is
    not a question the `manager` tool exists for.
    """

    @pytest.mark.parametrize(
        "value",
        ["/security/users/me", "/security/users/me/policies", "/security/users/me/"],
    )
    def test_self_introspection_is_reachable(self, value: str) -> None:
        assert validate_manager_path(value).startswith("/security/users/me")

    @pytest.mark.parametrize(
        "value",
        [
            "/security/users",  # every API account
            "/security/users/001",
            "/security/roles",
            "/security/policies",
            "/security/rules",
            "/security/actions",
            "/security/resources",
            "/security/config",
            "/security",
        ],
    )
    def test_rbac_enumeration_is_not(self, value: str) -> None:
        with pytest.raises(ValidationError, match="is not reachable through this tool"):
            validate_manager_path(value)

    def test_the_error_names_what_is_permitted(self) -> None:
        """A refusal a caller cannot act on is a refusal that gets worked around."""
        with pytest.raises(ValidationError) as excinfo:
            validate_manager_path("/security/users")
        assert "/security/users/me" in str(excinfo.value)

    def test_the_jwt_handshake_does_not_go_through_this_validator(self) -> None:
        """ManagerClient posts to MANAGER_AUTH_PATH directly.

        If it ever stopped doing so, restricting this root would break every
        manager call — so the coupling is asserted rather than assumed.
        """
        assert MANAGER_AUTH_PATH == "/security/user/authenticate"
        with pytest.raises(ValidationError):
            validate_manager_path(MANAGER_AUTH_PATH)

    def test_unrestricted_roots_are_unaffected(self) -> None:
        assert "agents" not in MANAGER_RESTRICTED_ROOTS
        assert validate_manager_path("/agents/001/config") == "/agents/001/config"

    def test_every_restricted_root_is_itself_allowlisted(self) -> None:
        """A restricted root that is not in the root allowlist is dead config."""
        for root, paths in MANAGER_RESTRICTED_ROOTS.items():
            assert root in MANAGER_PATH_ALLOWLIST
            for path in paths:
                assert path.split("/")[1] == root, f"{path} does not sit under {root}"
                assert validate_manager_path(path) == path


class TestValidateDetectorId:
    @pytest.mark.parametrize("value", ["x-dwFIYBT6_n8WeuQjo4", "MFRg1IMByX0LvTiGHtcN"])
    def test_accepts_plugin_ids(self, value: str) -> None:
        assert validate_detector_id(value) == value

    @pytest.mark.parametrize(
        "value", ["", "   ", "../detectors", "id/with/slash", "id with space", "a" * 129]
    )
    def test_rejects_invalid(self, value: str) -> None:
        with pytest.raises(ValidationError):
            validate_detector_id(value)


class TestValidatePrefix:
    @pytest.mark.parametrize(
        "value",
        [
            "wazuh.",
            "wazuh.agent.",
            "source.",
            "threat.",
            "event.original",
            "@timestamp",
            "wazuh.*.id",
            "a",
            "a" * 255,
        ],
    )
    def test_accepts_field_namespaces(self, value: str) -> None:
        assert validate_prefix(value) == value

    def test_strips_surrounding_whitespace(self) -> None:
        assert validate_prefix("  wazuh.  ") == "wazuh."

    @pytest.mark.parametrize("value", ["", "   "])
    def test_rejects_empty(self, value: str) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_prefix(value)

    def test_rejects_over_length(self) -> None:
        with pytest.raises(ValidationError, match="exceeds 255"):
            validate_prefix("a" * 256)

    @pytest.mark.parametrize(
        "value",
        [
            "../../../_cat/indices",  # traversal to the cluster root
            "wazuh./../../_cluster",
            "_mapping/field/x",  # a bare slash re-targets the endpoint
            "wazuh.?pretty=true",  # "?" terminates the path, "*" lands in the query
            "wazuh.#",  # "#" terminates the path and swallows the "*"
            "%2e%2e%2f_cat",  # percent-encoded traversal
            "wazuh\n.id",  # interior newline; a trailing one is stripped, not rejected
            "wazuh. id",
        ],
    )
    def test_rejects_anything_that_could_re_target_the_request(self, value: str) -> None:
        with pytest.raises(ValidationError):
            validate_prefix(value)


class TestPrefixCannotEscapeTheMappingEndpoint:
    """The reason validate_prefix exists, stated as the URL it prevents.

    `prefix` is interpolated into GET /{index}/_mapping/field/{prefix}* and httpx
    resolves dot segments against the base URL before sending, so an unguarded
    prefix is an arbitrary GET against the indexer with its credentials. These
    tests assert on the URL httpx would actually build, not on the validator's
    own opinion of the string.
    """

    BASE = "https://indexer.example:9200"
    INDEX = "wazuh-events-v5-*"

    def _url(self, prefix: str) -> str:
        with httpx.Client(base_url=self.BASE) as client:
            request = client.build_request(
                "GET", f"/{self.INDEX}/_mapping/field/{prefix}*"
            )
        return str(request.url)

    @pytest.mark.parametrize(
        "prefix,escaped",
        [
            ("../../../_cat/indices#", "https://indexer.example:9200/_cat/indices"),
            (
                "../../../_plugins/_security/api/internalusers#",
                "https://indexer.example:9200/_plugins/_security/api/internalusers",
            ),
            (
                "../../../_cluster/settings?",
                "https://indexer.example:9200/_cluster/settings?*",
            ),
        ],
    )
    def test_the_escape_is_real_and_the_validator_blocks_it(
        self, prefix: str, escaped: str
    ) -> None:
        # Without the guard the request leaves the /_mapping/field/ endpoint
        # entirely — three levels up reaches the cluster root.
        assert self._url(prefix) == escaped
        with pytest.raises(ValidationError):
            validate_prefix(prefix)

    def test_an_accepted_prefix_stays_under_the_mapping_endpoint(self) -> None:
        url = self._url(validate_prefix("wazuh.agent."))
        assert url == (
            "https://indexer.example:9200/wazuh-events-v5-*"
            "/_mapping/field/wazuh.agent.*"
        )
