# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The anonymization layer: masking rules, determinism, blocking, logging.

The guarantee this layer exists for is stated as: an external LLM client never
receives personal data. The tests pin the three mechanisms that add up to it —
the structured field pass (which knows what a field means), the text pass
(which catches the unambiguous value types anywhere), and the verify/block step
(which withholds output when a residual survives both).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from klaxon_mcp import overview as _overview
from klaxon_mcp import server
from klaxon_mcp.anonymization import (
    AGENT,
    EMAIL,
    HOST,
    IP,
    USER,
    Anonymizer,
    parse_agg_fields,
)
from klaxon_mcp.clients import Response
from klaxon_mcp.config import AnonymizationConfig


# Fixed test salt: the token helpers compute expected tokens with it, so `anon()`
# must inject the same salt into every Anonymizer it builds.
TEST_SALT = "klaxon-test-salt"


def anon(**overrides: Any) -> Anonymizer:
    overrides.setdefault("salt", TEST_SALT)
    return Anonymizer(
        AnonymizationConfig(enabled=overrides.pop("enabled", True), **overrides)
    )


def token(kind: str, value: str) -> str:
    digest = hmac.new(
        TEST_SALT.encode("utf-8"), f"{kind}:{value}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"[{kind}_{digest[:16]}]"


def ip_ph(value: str) -> str:
    return token(IP, value)


# --------------------------------------------------------------------------- #
# Activation: the switch is env/config-driven and local-aware
# --------------------------------------------------------------------------- #


class TestActive:
    def test_disabled_is_never_active(self) -> None:
        assert anon(enabled=False).active is False

    def test_enabled_external_endpoint_is_active(self) -> None:
        assert anon(llm_base_url="https://api.deepseek.com/v1").active is True

    def test_enabled_loopback_endpoint_is_inactive(self) -> None:
        # A local model (Ollama, vLLM on localhost) leaves data unchanged.
        assert anon(llm_base_url="http://localhost:11434").active is False
        assert anon(llm_base_url="http://127.0.0.1:8000/v1").active is False

    def test_enabled_unknown_endpoint_is_active(self) -> None:
        # No endpoint configured: assuming external is the GDPR-safe failure.
        assert anon(llm_base_url="").active is True


# --------------------------------------------------------------------------- #
# Value-type masking
# --------------------------------------------------------------------------- #


class TestValueMasking:
    def test_ipv4_is_masked(self) -> None:
        out = anon().mask_text("login from 192.168.1.100 failed")
        assert "192.168.1.100" not in out
        assert ip_ph("192.168.1.100") in out

    def test_ipv6_is_masked(self) -> None:
        out = anon().mask_text("from 2001:db8:85a3::8a2e:370:7334 ok")
        assert "2001:db8:85a3::8a2e:370:7334" not in out
        assert "[IP_" in out

    def test_email_is_masked(self) -> None:
        out = anon().mask_text("contact user@example.com now")
        assert "user@example.com" not in out
        assert token(EMAIL, "user@example.com") in out

    def test_port_numbers_and_versions_are_not_ips(self) -> None:
        out = anon().mask_text("listen on :9200, version 1.2.3, pattern wazuh-events-v5-*")
        assert ":9200" in out
        assert "1.2.3" in out
        assert "wazuh-events-v5-*" in out

    def test_no_hash_uses_generic_labels(self) -> None:
        out = anon(use_hash=False).mask_text("from 192.168.1.100 via user@example.com")
        assert "[IP_ADDRESS]" in out
        assert "[EMAIL]" in out

    def test_spec_free_text_example(self) -> None:
        """The spec's canonical case: username and IP both masked in one line."""
        out = anon().mask_text("Failed login for admin from 192.168.1.100")
        assert "admin" not in out
        assert "192.168.1.100" not in out
        assert "[USER_" in out
        assert "[IP_" in out

    def test_free_text_username_does_not_swallow_an_ip(self) -> None:
        """'login from <ip>' is a source address, not a username."""
        out = anon().mask_text("Failed login from 192.168.1.100")
        assert "192.168.1.100" not in out
        assert "[IP_" in out
        assert "[USER_" not in out

    def test_free_text_username_does_not_swallow_prose(self) -> None:
        out = anon().mask_text("Prevent access from external hosts")
        assert out == "Prevent access from external hosts"

    def test_username_context_forms(self) -> None:
        for line in (
            "user=admin attempted",
            "username: root accepted",
            "login as operator ok",
            "authenticated as svc_backup",
            "login by user marco from host",
        ):
            out = anon().mask_text(line)
            assert "[USER_" in out, f"expected a username mask in {line!r}"


# --------------------------------------------------------------------------- #
# Non-string scalars under configured fields (M1): a numeric user.id / agent.id
# must be masked like its string twin; None and non-configured numbers pass.
# --------------------------------------------------------------------------- #


class TestNonStringScalarMasking:
    def test_numeric_configured_source_field_masked(self) -> None:
        masked = anon().mask_json(
            {"hits": {"_source": {"user.id": 1001, "agent.id": 7}}}
        )
        source = masked["hits"]["_source"]
        assert source["user.id"] == token(USER, "1001")
        assert source["agent.id"] == token(AGENT, "7")

    def test_float_and_bool_configured_field_masked(self) -> None:
        masked = anon().mask_json({"source.ip": 1.5})
        assert masked["source.ip"] == token(IP, "1.5")

    def test_non_configured_numeric_values_untouched(self) -> None:
        doc = {"user.id": 1001, "bytes": 2048, "ok": True, "score": 0.5}
        masked = anon().mask_json(doc)
        assert masked["user.id"] == token(USER, "1001")
        assert masked["bytes"] == 2048
        assert masked["ok"] is True
        assert masked["score"] == 0.5

    def test_none_under_configured_field_stays_none(self) -> None:
        masked = anon().mask_json({"user.id": None})
        assert masked["user.id"] is None

    def test_numeric_aggregation_key_on_configured_field_masked(self) -> None:
        """Numeric terms keys / composite after_key stay identical to _source."""
        body = {"aggs": {"ids": {"terms": {"field": "user.id"}}}}
        response = Response(
            200,
            json.dumps(
                {"aggregations": {"ids": {"buckets": [{"key": 1001, "doc_count": 5}]}}}
            ),
            "https://indexer.example/_search",
        )
        a = anon(mask_aggregation_keys=True)
        masked = a.mask_response(response, agg_map=parse_agg_fields(body)).json()
        assert masked["aggregations"]["ids"]["buckets"][0]["key"] == token(USER, "1001")

    def test_numeric_composite_after_key_on_configured_field_masked(self) -> None:
        body = {
            "aggs": {
                "c": {"composite": {"sources": [{"uid": {"terms": {"field": "user.id"}}}]}}
            }
        }
        response = Response(
            200,
            json.dumps(
                {
                    "aggregations": {
                        "c": {
                            "after_key": {"uid": 1001},
                            "buckets": [{"key": {"uid": 1001}, "doc_count": 5}],
                        }
                    }
                }
            ),
            "https://indexer.example/_search",
        )
        a = anon(mask_aggregation_keys=True)
        masked = a.mask_response(response, agg_map=parse_agg_fields(body)).json()
        assert masked["aggregations"]["c"]["after_key"]["uid"] == token(USER, "1001")
        assert masked["aggregations"]["c"]["buckets"][0]["key"]["uid"] == token(USER, "1001")

# --------------------------------------------------------------------------- #
# Deterministic placeholders
# --------------------------------------------------------------------------- #


class TestDeterminism:
    def test_same_input_same_placeholder(self) -> None:
        a = anon()
        b = anon()
        assert a.mask_text("host 192.168.1.100") == b.mask_text("host 192.168.1.100")

    def test_different_inputs_different_placeholders(self) -> None:
        a = anon().mask_text("1.2.3.4")
        b = anon().mask_text("5.6.7.8")
        assert a != b

    def test_masked_value_is_a_placeholder_in_full(self) -> None:
        out = anon().mask_text("10.0.0.1")
        assert out == ip_ph("10.0.0.1")


class TestHmacTokens:
    def test_token_is_hmac_with_64_bits_of_output(self) -> None:
        assert re.fullmatch(r"\[USER_[0-9a-f]{16}\]", token(USER, "marcomoenig"))

    def test_same_value_different_families_differ(self) -> None:
        assert token(HOST, "web01") != token(USER, "web01")

    def test_same_family_same_value_same_token(self) -> None:
        assert token(USER, "admin") == token(USER, "admin")

    def test_different_salts_give_different_tokens(self) -> None:
        a = Anonymizer(AnonymizationConfig(enabled=True, salt="salt-a"))
        b = Anonymizer(AnonymizationConfig(enabled=True, salt="salt-b"))
        assert a.mask_text("10.0.0.1") != b.mask_text("10.0.0.1")

    def test_same_salt_same_token_across_instances(self) -> None:
        a = Anonymizer(AnonymizationConfig(enabled=True, salt="salt-x"))
        b = Anonymizer(AnonymizationConfig(enabled=True, salt="salt-x"))
        assert a.mask_text("10.0.0.1") == b.mask_text("10.0.0.1")


# --------------------------------------------------------------------------- #
# Structured, field-aware masking
# --------------------------------------------------------------------------- #


class TestFieldAwareMasking:
    def test_source_ip_field(self) -> None:
        doc = {"_source": {"source": {"ip": "192.168.1.100"}}}
        out = anon().mask_json(doc)
        assert out["_source"]["source"]["ip"] == ip_ph("192.168.1.100")

    def test_nested_user_name_field(self) -> None:
        doc = {"hits": {"hits": [{"_source": {"user": {"name": "admin"}}}]}}
        out = anon().mask_json(doc)
        assert out["hits"]["hits"][0]["_source"]["user"]["name"].startswith("[USER_")

    def test_wazuh_agent_name_and_id(self) -> None:
        doc = {
            "_source": {
                "wazuh": {"agent": {"name": "web-server-01", "id": "001"}},
            }
        }
        out = anon().mask_json(doc)
        assert out["_source"]["wazuh"]["agent"]["name"].startswith("[HOST_")
        assert out["_source"]["wazuh"]["agent"]["id"].startswith("[AGENT_")

    def test_same_value_same_placeholder_across_documents(self) -> None:
        a = anon()
        one = a.mask_json({"_source": {"user": {"name": "admin"}}})
        two = a.mask_json({"_source": {"user": {"name": "admin"}}})
        assert one["_source"]["user"]["name"] == two["_source"]["user"]["name"]

    def test_free_text_fields_get_embedded_ip_masking(self) -> None:
        doc = {"_source": {"event": {"original": "Failed login from 192.168.1.100"}}}
        out = anon().mask_json(doc)
        assert "192.168.1.100" not in out["_source"]["event"]["original"]
        assert "[IP_" in out["_source"]["event"]["original"]

    def test_mask_response_clones_and_masks_json(self) -> None:
        a = anon()
        response = Response(
            200,
            json.dumps({"_source": {"user": {"name": "admin"}}}),
            "https://indexer.example/x",
        )
        masked = a.mask_response(response)
        assert masked is not response
        assert "admin" not in masked.text
        assert "[USER_" in masked.text

    def test_mask_response_leaves_non_json_alone(self) -> None:
        a = anon()
        response = Response(200, "not json at all", "https://indexer.example/x")
        assert a.mask_response(response) is response


class TestMaskOverview:
    def test_agent_names_are_masked(self) -> None:
        result = _overview.parse(
            {
                "hits": {"total": {"value": 10, "relation": "eq"}},
                "aggregations": {
                    "agents": {
                        "buckets": [
                            {"key": "web-server-01", "doc_count": 6},
                            {"key": "opnsense", "doc_count": 4},
                        ],
                        "sum_other_doc_count": 0,
                    },
                    "agent_count": {"value": 2},
                },
            }
        )
        masked = anon().mask_overview(result)
        names = [b.key for b in masked.agents]
        assert all(not n.startswith("web-server-01") and not n.startswith("opnsense") for n in names)
        assert all(n.startswith("[HOST_") for n in names)
        assert masked.agents[0].count == 6


class TestFreeTextUsernameMasking:
    """Gap 1: usernames inside free-text fields get the same tokens as the
    structured fields, without false-positive prose masking."""

    MASK_FIELDS = (
        "user.name",
        "user.id",
        "related.user",
        "user.effective.name",
        "source.ip",
    )

    def mask_doc(self, doc: dict[str, Any]) -> tuple[dict[str, Any], Anonymizer]:
        a = anon(mask_fields=self.MASK_FIELDS)
        response = Response(
            200,
            json.dumps({"hits": {"hits": [{"_source": doc}]}}),
            "https://indexer.example/_search",
        )
        out = a.mask_response(response).json()
        return out["hits"]["hits"][0]["_source"], a

    def test_ldap_dn_uid_matches_structured_token(self) -> None:
        source, _ = self.mask_doc(
            {
                "user": {"name": "marcomoenig"},
                "message": (
                    'conn=1086 op=13353 ENTRY dn="uid=marcomoenig,'
                    'ou=users,dc=sec73,dc=io"'
                ),
            }
        )
        assert source["user"]["name"] == token(USER, "marcomoenig")
        assert source["message"] == (
            'conn=1086 op=13353 ENTRY dn="uid='
            + token(USER, "marcomoenig")
            + ',ou=users,dc=sec73,dc=io"'
        )

    def test_pam_session_line_both_usernames_masked(self) -> None:
        source, _ = self.mask_doc(
            {
                "user": {"name": "root"},
                "message": (
                    "pam_unix(sshd:session): session opened for user "
                    "root(uid=0) by root(uid=0)"
                ),
            }
        )
        u = token(USER, "root")
        assert source["message"] == (
            f"pam_unix(sshd:session): session opened for user {u}(uid=0) "
            f"by {u}(uid=0)"
        )

    def test_ssh_publickey_line_masks_user_and_ip(self) -> None:
        source, _ = self.mask_doc(
            {
                "user": {"name": "root"},
                "message": "Accepted publickey for root from 192.168.1.5 port 46638",
            }
        )
        assert source["message"] == (
            f"Accepted publickey for {token(USER, 'root')} "
            f"from {ip_ph('192.168.1.5')} port 46638"
        )

    def test_user_effective_name_whole_value_masked(self) -> None:
        source, _ = self.mask_doc(
            {
                "user": {"effective": {"name": "root(uid=0)"}},
                "message": "auth attempt by root(uid=0) rejected",
            }
        )
        assert source["user"]["effective"]["name"] == token(USER, "root(uid=0)")
        # The literal effective-name value in free text reuses its own token
        # (registry runs before the context patterns), so `_source` and
        # `message` stay consistent for the same value.
        assert source["message"] == (
            f"auth attempt by {token(USER, 'root(uid=0)')} rejected"
        )

    def test_known_identity_replaced_in_unrecognized_position(self) -> None:
        source, _ = self.mask_doc(
            {
                "user": {"name": "marcomoenig"},
                "message": "marcomoenig opened a session",
            }
        )
        assert source["message"] == f"{token(USER, 'marcomoenig')} opened a session"

    def test_common_word_not_blindly_replaced(self) -> None:
        # "root" is a known identity here, but masking it in generic prose is the
        # false positive the stoplist avoids; context patterns still catch it in
        # username formulations.
        source, _ = self.mask_doc(
            {
                "user": {"name": "root"},
                "message": "the root filesystem check passed",
            }
        )
        assert source["message"] == "the root filesystem check passed"

    def test_free_text_users_off_restores_today_behaviour(self) -> None:
        a = anon(mask_fields=self.MASK_FIELDS, mask_free_text_users=False)
        doc = {
            "user": {"name": "marcomoenig"},
            "message": 'dn="uid=marcomoenig,ou=users,dc=sec73,dc=io"',
        }
        response = Response(
            200,
            json.dumps({"hits": {"hits": [{"_source": doc}]}}),
            "https://indexer.example/_search",
        )
        out = a.mask_response(response).json()["hits"]["hits"][0]["_source"]
        assert out["user"]["name"] == token(USER, "marcomoenig")
        assert out["message"] == 'dn="uid=marcomoenig,ou=users,dc=sec73,dc=io"'

    def test_bare_user_does_not_mask_common_words(self) -> None:
        # Security-review finding 1: "user <common English word>" in prose must
        # not be masked — the guard is derived from the full stoplist.
        for phrase in (
            "the user system reported",
            "user policy requires",
            "the user root directory",
            "user manager said",
        ):
            assert anon().mask_text(phrase) == phrase

    def test_bare_user_masks_distinctive_name(self) -> None:
        out = anon().mask_text("user marcomoenig logged in")
        assert token(USER, "marcomoenig") in out
        assert "marcomoenig" not in out

    def test_case_variant_maps_to_structured_token(self) -> None:
        # Security-review finding 2: a case-shifted username in free text reuses
        # the structured token (registry runs before the context patterns).
        source, _ = self.mask_doc(
            {
                "user": {"name": "MarcoMoenig"},
                "message": "uid=marcomoenig,ou=users,dc=sec73,dc=io",
            }
        )
        structured = token(USER, "MarcoMoenig")
        assert source["user"]["name"] == structured
        assert source["message"] == (
            "uid=" + structured + ",ou=users,dc=sec73,dc=io"
        )

    def test_unicode_username_masked_consistently(self) -> None:
        # Security-review finding 2: German umlauts are handled and share the
        # structured token, in both registry and context-pattern positions.
        source, _ = self.mask_doc(
            {
                "user": {"name": "Müller"},
                "message": "login as müller from 10.0.0.9; uid=Müller,ou=users",
            }
        )
        structured = token(USER, "Müller")
        assert source["user"]["name"] == structured
        message = source["message"]
        assert structured in message
        assert "müller" not in message
        assert "Müller" not in message
        assert ip_ph("10.0.0.9") in message

    def test_identity_from_one_hit_does_not_mask_prose_in_another(self) -> None:
        # Security-review finding 3: identities are scoped per document, so a
        # username in one hit must not mask the same word in prose in another.
        a = anon(mask_fields=self.MASK_FIELDS)
        payload = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "user": {"name": "marcomoenig"},
                            "message": "uid=marcomoenig,ou=users",
                        }
                    },
                    {"_source": {"message": "the marcomoenig cena movie"}},
                ]
            }
        }
        response = Response(
            200, json.dumps(payload), "https://indexer.example/_search"
        )
        hits = a.mask_response(response).json()["hits"]["hits"]
        assert hits[0]["_source"]["user"]["name"] == token(USER, "marcomoenig")
        # Same-document prose is still masked via the per-document registry.
        assert hits[0]["_source"]["message"] == (
            "uid=" + token(USER, "marcomoenig") + ",ou=users"
        )
        # The second document's prose is untouched (no cross-document registry).
        assert hits[1]["_source"]["message"] == "the marcomoenig cena movie"

    def test_email_and_ip_still_masked_everywhere(self) -> None:
        # Regression: the value-type passes are untouched by the username pass.
        source, _ = self.mask_doc(
            {
                "user": {"name": "marcomoenig"},
                "message": (
                    "login for marcomoenig from 192.168.1.5 contact "
                    "marco@sec73.io"
                ),
            }
        )
        message = source["message"]
        assert token(USER, "marcomoenig") in message
        assert ip_ph("192.168.1.5") in message
        assert token(EMAIL, "marco@sec73.io") in message
        assert "marcomoenig" not in message
        assert "192.168.1.5" not in message
        assert "marco@sec73.io" not in message


# --------------------------------------------------------------------------- #
# Verify and block
# --------------------------------------------------------------------------- #


class TestVerify:
    def test_clean_output_has_no_residuals(self) -> None:
        a = anon()
        masked = a.mask_text("all clean now [IP_abc123]")
        assert a.verify(masked) == []

    def test_residual_ip_is_detected(self) -> None:
        assert anon().verify("something 10.20.30.40 slipped through") == ["IP"]

    def test_residual_email_is_detected(self) -> None:
        assert anon().verify("contact me@example.org") == ["EMAIL"]


class TestBlocking:
    def test_finish_returns_masked_when_clean(self, tmp_path: Any) -> None:
        a = anon(log_path=str(tmp_path / "llm_prompts.log"))
        raw = "login from 192.168.1.100"
        out = a.finish("search", raw, a.mask_text(raw))
        assert "192.168.1.100" not in out
        assert "[IP_" in out
        assert "GDPR BLOCKED" not in out

    def test_finish_blocks_on_residual(self, tmp_path: Any) -> None:
        # A masked output that still carries an IP simulates a masking gap:
        # whitelist semantics mean such a response must not go out.
        a = anon(whitelist_enabled=True, log_path=str(tmp_path / "llm_prompts.log"))
        out = a.finish("search", "raw: 192.168.1.100", "masked but 10.0.0.5 remained")
        assert "GDPR BLOCKED" in out
        assert "10.0.0.5" not in out

    def test_whitelist_disabled_logs_but_returns_masked(self, tmp_path: Any) -> None:
        a = anon(
            whitelist_enabled=False, log_path=str(tmp_path / "llm_prompts.log")
        )
        out = a.finish("search", "raw", "masked but 10.0.0.5 remained")
        assert "GDPR BLOCKED" not in out
        assert out == "masked but 10.0.0.5 remained"


# --------------------------------------------------------------------------- #
# Audit logging and export
# --------------------------------------------------------------------------- #


class TestAuditLog:
    def test_masked_line_is_written_no_raw_by_default(
        self, tmp_path: Any
    ) -> None:
        log = str(tmp_path / "llm_prompts.log")
        a = anon(log_path=log)
        a.finish("search", "raw has 192.168.1.100", "masked output")
        with open(log, "r", encoding="utf-8") as fh:
            content = fh.read()
        assert "MASKED" in content
        assert "RAW" not in content
        assert "192.168.1.100" not in content

    def test_raw_logging_is_explicit(self, tmp_path: Any) -> None:
        log = str(tmp_path / "llm_prompts.log")
        a = anon(log_path=log, log_raw=True)
        a.finish("search", "raw has 192.168.1.100", "masked output")
        with open(log, "r", encoding="utf-8") as fh:
            content = fh.read()
        assert "RAW" in content
        assert "192.168.1.100" in content

    def test_export_drops_raw_lines(self, tmp_path: Any) -> None:
        log = str(tmp_path / "llm_prompts.log")
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("ts - [EXTERNAL_LLM] - search RAW: 192.168.1.100\n")
            fh.write("ts - [EXTERNAL_LLM] - search MASKED: [IP_abc123]\n")
        exported = Anonymizer.export_masked_log(log)
        assert "192.168.1.100" not in exported
        assert "[IP_abc123]" in exported
        assert "RAW" not in exported


class TestReport:
    def test_report_contains_no_raw_pii(self) -> None:
        a = anon()
        a.mask_json({"_source": {"user": {"name": "admin"}}})
        a.mask_text("from 192.168.1.100")
        report = a.report_text()
        assert "admin" not in report
        assert "192.168.1.100" not in report
        assert "[USER_" in report
        assert "[IP_" in report

    def test_status_says_disabled(self) -> None:
        a = Anonymizer(AnonymizationConfig(enabled=False))
        assert "DISABLED" in a.status_text()


# --------------------------------------------------------------------------- #
# Aggregation-key masking: the `aggregations` block leaks nothing it should not
# --------------------------------------------------------------------------- #


def ph(kind: str, value: str) -> str:
    return token(kind, value)


# The 18-field mask list from the feature spec; representative of a real config.
MASK_FIELDS_18: tuple[str, ...] = (
    "destination.ip",
    "source.ip",
    "user.name",
    "user.id",
    "client.user.name",
    "related.ip",
    "related.user",
    "related.hosts",
    "source.address",
    "source.domain",
    "url.domain",
    "host.hostname",
    "wazuh.agent.id",
    "wazuh.agent.name",
    "wazuh.agent.host.hostname",
    "event.dataset",
    "event.original",
    "log.logger",
)


class TestAggregationKeyMasking:
    """Aggregation bucket keys are masked with the same tokens as `_source`."""

    def agg_anon(self, **overrides: Any) -> Anonymizer:
        return anon(
            mask_aggregation_keys=True,
            mask_fields=MASK_FIELDS_18,
            **overrides,
        )

    def mask(self, response_body: Any, request_body: Any) -> tuple[Any, Anonymizer]:
        a = self.agg_anon()
        response = Response(
            200, json.dumps(response_body), "https://indexer.example/_search"
        )
        masked = a.mask_response(response, agg_map=parse_agg_fields(request_body))
        return masked.json(), a

    def test_terms_on_related_hosts_masked(self) -> None:
        body = {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        response = {
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {"key": "nc02web", "doc_count": 5},
                        {"key": "yun", "doc_count": 3},
                    ],
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 1,
                }
            }
        }
        masked, _ = self.mask(response, body)
        agg = masked["aggregations"]["hosts"]
        assert [b["key"] for b in agg["buckets"]] == [
            ph("HOST", "nc02web"),
            ph("HOST", "yun"),
        ]
        # counts and metadata are untouched
        assert [b["doc_count"] for b in agg["buckets"]] == [5, 3]
        assert agg["doc_count_error_upper_bound"] == 0
        assert agg["sum_other_doc_count"] == 1

    def test_terms_on_user_name_masked(self) -> None:
        body = {"aggs": {"users": {"terms": {"field": "user.name"}}}}
        response = {
            "aggregations": {
                "users": {
                    "buckets": [
                        {"key": "root", "doc_count": 7},
                        {"key": "marcomoenig", "doc_count": 1},
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        assert [b["key"] for b in masked["aggregations"]["users"]["buckets"]] == [
            ph("USER", "root"),
            ph("USER", "marcomoenig"),
        ]

    def test_agg_key_token_equals_source_token(self) -> None:
        """One entity -> one token in `_source` and in the aggregation key."""
        body = {"aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        response = {
            "hits": {
                "hits": [
                    {"_source": {"related": {"hosts": ["nc02web", "yun"]}}},
                ]
            },
            "aggregations": {
                "hosts": {"buckets": [{"key": "nc02web", "doc_count": 5}]}
            },
        }
        masked, _ = self.mask(response, body)
        assert masked["hits"]["hits"][0]["_source"]["related"]["hosts"] == [
            ph("HOST", "nc02web"),
            ph("HOST", "yun"),
        ]
        assert masked["aggregations"]["hosts"]["buckets"][0]["key"] == ph(
            "HOST", "nc02web"
        )

    def test_terms_on_unmasked_field_unchanged(self) -> None:
        body = {
            "aggs": {"cats": {"terms": {"field": "wazuh.integration.category"}}}
        }
        response = {
            "aggregations": {
                "cats": {
                    "buckets": [
                        {"key": "cloud-services", "doc_count": 2},
                        {"key": "security", "doc_count": 1},
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        assert [b["key"] for b in masked["aggregations"]["cats"]["buckets"]] == [
            "cloud-services",
            "security",
        ]

    def test_date_histogram_keys_unchanged(self) -> None:
        body = {
            "aggs": {
                "by_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "day",
                    }
                }
            }
        }
        response = {
            "aggregations": {
                "by_time": {
                    "buckets": [
                        {
                            "key_as_string": "2026-08-09T00:00:00.000Z",
                            "key": 1754697600000,
                            "doc_count": 4,
                        },
                        {
                            "key_as_string": "2026-08-10T00:00:00.000Z",
                            "key": 1754784000000,
                            "doc_count": 6,
                        },
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        buckets = masked["aggregations"]["by_time"]["buckets"]
        assert buckets[0]["key_as_string"] == "2026-08-09T00:00:00.000Z"
        assert buckets[0]["key"] == 1754697600000
        assert buckets[1]["doc_count"] == 6

    def test_nested_sub_aggregations_masked_at_both_levels(self) -> None:
        body = {
            "aggs": {
                "agents": {
                    "terms": {"field": "wazuh.agent.name"},
                    "aggs": {
                        "categories": {
                            "terms": {"field": "wazuh.integration.category"}
                        }
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "agents": {
                    "buckets": [
                        {
                            "key": "web-server-01",
                            "doc_count": 3,
                            "aggregations": {
                                "categories": {
                                    "buckets": [
                                        {"key": "cloud-services", "doc_count": 2},
                                        {"key": "security", "doc_count": 1},
                                    ]
                                }
                            },
                        },
                        {
                            "key": "opnsense",
                            "doc_count": 2,
                            "aggregations": {
                                "categories": {
                                    "buckets": [
                                        {"key": "network-activity", "doc_count": 2}
                                    ]
                                }
                            },
                        },
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        agents = masked["aggregations"]["agents"]["buckets"]
        assert agents[0]["key"] == ph("HOST", "web-server-01")
        assert agents[1]["key"] == ph("HOST", "opnsense")
        assert [b["doc_count"] for b in agents] == [3, 2]
        assert [
            c["key"] for c in agents[0]["aggregations"]["categories"]["buckets"]
        ] == ["cloud-services", "security"]

    def test_composite_masks_key_and_after_key(self) -> None:
        body = {
            "aggs": {
                "comp": {
                    "composite": {
                        "sources": [
                            {"src_ip": {"terms": {"field": "source.ip"}}},
                            {"username": {"terms": {"field": "user.name"}}},
                        ]
                    }
                }
            }
        }
        response = {
            "aggregations": {
                "comp": {
                    "after_key": {"src_ip": "10.0.0.1", "username": "admin"},
                    "buckets": [
                        {
                            "key": {"src_ip": "10.0.0.1", "username": "admin"},
                            "doc_count": 4,
                        },
                        {
                            "key": {"src_ip": "10.0.0.2", "username": "root"},
                            "doc_count": 2,
                        },
                    ],
                }
            }
        }
        masked, _ = self.mask(response, body)
        comp = masked["aggregations"]["comp"]
        assert comp["after_key"] == {
            "src_ip": ph("IP", "10.0.0.1"),
            "username": ph("USER", "admin"),
        }
        assert comp["buckets"][0]["key"] == {
            "src_ip": ph("IP", "10.0.0.1"),
            "username": ph("USER", "admin"),
        }
        assert comp["buckets"][1]["key"] == {
            "src_ip": ph("IP", "10.0.0.2"),
            "username": ph("USER", "root"),
        }
        assert [b["doc_count"] for b in comp["buckets"]] == [4, 2]

    def test_multi_terms_masks_only_masked_element(self) -> None:
        body = {
            "aggs": {
                "pairs": {
                    "multi_terms": {
                        "terms": [
                            {"field": "user.name"},
                            {"field": "wazuh.integration.category"},
                        ]
                    }
                }
            }
        }
        response = {
            "aggregations": {
                "pairs": {
                    "buckets": [{"key": ["root", "cloud-services"], "doc_count": 3}]
                }
            }
        }
        masked, _ = self.mask(response, body)
        assert masked["aggregations"]["pairs"]["buckets"][0]["key"] == [
            ph("USER", "root"),
            "cloud-services",
        ]

    def test_filters_named_keys_untouched(self) -> None:
        body = {
            "aggs": {
                "f": {
                    "filters": {
                        "filters": {
                            "admin-logins": {"term": {"user.name": "root"}},
                            "everything-else": {"match_all": {}},
                        }
                    }
                }
            }
        }
        response = {
            "aggregations": {
                "f": {
                    "buckets": {
                        "admin-logins": {"doc_count": 2},
                        "everything-else": {"doc_count": 10},
                    }
                }
            }
        }
        masked, _ = self.mask(response, body)
        assert list(masked["aggregations"]["f"]["buckets"].keys()) == [
            "admin-logins",
            "everything-else",
        ]
        assert masked["aggregations"]["f"]["buckets"]["admin-logins"]["doc_count"] == 2

    def test_top_hits_embedded_source_masked(self) -> None:
        body = {"aggs": {"top": {"top_hits": {"size": 1}}}}
        response = {
            "aggregations": {
                "top": {
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "user": {"name": "admin"},
                                    "source": {"ip": "10.0.0.9"},
                                }
                            }
                        ]
                    }
                }
            }
        }
        masked, _ = self.mask(response, body)
        src = masked["aggregations"]["top"]["hits"]["hits"][0]["_source"]
        assert src["user"]["name"] == ph("USER", "admin")
        assert src["source"]["ip"] == ph("IP", "10.0.0.9")

    def test_unknown_agg_keys_left_alone(self) -> None:
        # scripted / opaque request: no spec -> never guess at the key
        body = {"aggs": {"custom": {"terms": {"script": {"source": "..."}}}}}
        response = {
            "aggregations": {
                "custom": {"buckets": [{"key": "nc02web", "doc_count": 1}]}
            }
        }
        masked, _ = self.mask(response, body)
        assert masked["aggregations"]["custom"]["buckets"][0]["key"] == "nc02web"

    def test_already_tokenized_value_is_re_tokenised_not_crashed(self) -> None:
        body = {"aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        response = {
            "aggregations": {
                "hosts": {"buckets": [{"key": "[HOST_abc123]", "doc_count": 1}]}
            }
        }
        masked, _ = self.mask(response, body)
        key = masked["aggregations"]["hosts"]["buckets"][0]["key"]
        assert key.startswith("[HOST_")
        assert key == ph("HOST", "[HOST_abc123]")

    def test_significant_terms_masked(self) -> None:
        body = {"aggs": {"sig": {"significant_terms": {"field": "user.name"}}}}
        response = {
            "aggregations": {"sig": {"buckets": [{"key": "root", "doc_count": 5}]}}
        }
        masked, _ = self.mask(response, body)
        assert masked["aggregations"]["sig"]["buckets"][0]["key"] == ph(
            "USER", "root"
        )

    def test_feature_off_leaves_aggregation_keys_as_before(self) -> None:
        # Explicit opt-out (the default is now fail-closed ON; turning it off
        # restores the pre-feature behaviour).
        a = anon(mask_aggregation_keys=False)
        body = {"aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        response = Response(
            200,
            json.dumps(
                {
                    "aggregations": {
                        "hosts": {"buckets": [{"key": "nc02web", "doc_count": 5}]}
                    }
                }
            ),
            "https://indexer.example/_search",
        )
        masked = a.mask_response(response, agg_map=parse_agg_fields(body))
        assert masked is not response
        assert masked.json()["aggregations"]["hosts"]["buckets"][0]["key"] == "nc02web"

    def test_no_aggregations_is_unchanged(self) -> None:
        body = {"query": {"match_all": {}}}
        response = {"hits": {"hits": []}}
        masked, _ = self.mask(response, body)
        assert masked == response


class TestParseAggFields:
    def test_terms(self) -> None:
        spec = parse_agg_fields(
            {"aggs": {"a": {"terms": {"field": "user.name"}}}}
        )["a"]
        assert spec.agg_type == "terms"
        assert spec.fields == ("user.name",)

    def test_multi_terms(self) -> None:
        spec = parse_agg_fields(
            {
                "aggs": {
                    "a": {
                        "multi_terms": {
                            "terms": [
                                {"field": "user.name"},
                                {"field": "related.hosts"},
                            ]
                        }
                    }
                }
            }
        )["a"]
        assert spec.agg_type == "multi_terms"
        assert spec.fields == ("user.name", "related.hosts")

    def test_composite_sources(self) -> None:
        spec = parse_agg_fields(
            {
                "aggs": {
                    "a": {
                        "composite": {
                            "sources": [
                                {"src_ip": {"terms": {"field": "source.ip"}}},
                                {"username": {"terms": {"field": "user.name"}}},
                            ]
                        }
                    }
                }
            }
        )["a"]
        assert spec.agg_type == "composite"
        assert spec.sources == (
            ("src_ip", "source.ip"),
            ("username", "user.name"),
        )

    def test_significant_terms_and_text(self) -> None:
        sig = parse_agg_fields(
            {"aggs": {"a": {"significant_terms": {"field": "user.id"}}}}
        )["a"]
        assert sig.agg_type == "significant_terms"
        assert sig.fields == ("user.id",)
        text = parse_agg_fields(
            {"aggs": {"a": {"significant_text": {"field": "event.original"}}}}
        )["a"]
        assert text.agg_type == "significant_text"
        assert text.fields == ("event.original",)

    def test_top_hits_is_a_marker(self) -> None:
        spec = parse_agg_fields({"aggs": {"a": {"top_hits": {"size": 1}}}})["a"]
        assert spec.agg_type == "top_hits"

    def test_non_field_aggs_are_none(self) -> None:
        for agg in (
            {"date_histogram": {"field": "@timestamp"}},
            {"histogram": {"field": "bytes"}},
            {"range": {"field": "bytes"}},
            {"sum": {"field": "bytes"}},
            {"cardinality": {"field": "user.name"}},
            {"filters": {"filters": {}}},
        ):
            spec = parse_agg_fields({"aggs": {"a": agg}})["a"]
            assert spec.agg_type is None
            assert spec.fields == ()
            assert spec.sources == ()

    def test_nested_aggs_are_recorded(self) -> None:
        specs = parse_agg_fields(
            {
                "aggs": {
                    "agents": {
                        "terms": {"field": "wazuh.agent.name"},
                        "aggs": {
                            "categories": {
                                "terms": {"field": "wazuh.integration.category"}
                            }
                        },
                    }
                }
            }
        )
        assert specs["agents"].fields == ("wazuh.agent.name",)
        assert specs["categories"].fields == ("wazuh.integration.category",)

    def test_opaque_body_yields_empty(self) -> None:
        assert parse_agg_fields({"query": {"match_all": {}}}) == {}
        assert parse_agg_fields(None) == {}
        assert parse_agg_fields({"aggs": "not-a-dict"}) == {}


# --------------------------------------------------------------------------- #
# Server integration: _render masks output only when active
# --------------------------------------------------------------------------- #


class RecordingIndexer:
    def __init__(self, payload: Any) -> None:
        self.payload = payload

    async def post(self, path: str, body: Any = None) -> Response:
        return Response(
            200, json.dumps(self.payload), f"https://indexer.example{path}"
        )


@pytest.fixture
def indexer() -> Iterator[RecordingIndexer]:
    from klaxon_mcp.config import Config

    previous = server._indexer
    previous_config = server._config
    server._config = Config(
        indexer_url="https://indexer.example:9200",
        indexer_user="",
        indexer_password="",
        manager_url="",
        manager_user="",
        manager_password="",
        engine_url="",
        verify_ssl=False,
        timeout=60.0,
        schema_field_limit=200,
        schema_probe_batch=100,
        search_max_size=100,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
    )
    server._indexer = RecordingIndexer(
        {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": []}}
    )
    try:
        yield server._indexer  # type: ignore[misc]
    finally:
        server._indexer = previous
        server._config = previous_config


@pytest.fixture
def active_server() -> Iterator[None]:
    """Install an active anonymizer on the server module, reset afterwards."""
    previous_anon = server._anonymizer
    server._anonymizer = Anonymizer(AnonymizationConfig(enabled=True, log_path="/tmp/klaxon-test-anon.log"))
    try:
        yield
    finally:
        server._anonymizer = previous_anon


class TestCli:
    """The one-shot --anonymization-* commands need no Wazuh environment."""

    def test_status_enabled(self, capsys: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        from klaxon_mcp.__main__ import main

        monkeypatch.setenv("KLAXON_ANONYMIZE_EXTERNAL_LLM", "true")
        assert main(["--anonymization-status"]) == 0
        assert "Anonymization: ENABLED" in capsys.readouterr().out

    def test_status_disabled(
        self, capsys: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from klaxon_mcp.__main__ import main

        monkeypatch.delenv("KLAXON_ANONYMIZE_EXTERNAL_LLM", raising=False)
        assert main(["--anonymization-status"]) == 0
        assert "DISABLED" in capsys.readouterr().out

    def test_report_writes_file(
        self, capsys: Any, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from klaxon_mcp.__main__ import main

        monkeypatch.delenv("KLAXON_ANONYMIZE_EXTERNAL_LLM", raising=False)
        out = tmp_path / "report.txt"
        assert main(["--anonymization-report", str(out)]) == 0
        assert "report written" in capsys.readouterr().out
        assert out.exists()

    def test_export_from_missing_log(
        self, capsys: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from klaxon_mcp.__main__ import main

        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_LOG", "/nonexistent/dir/llm_prompts.log"
        )
        assert main(["--anonymization-export"]) == 1
        assert "export failed" in capsys.readouterr().err


class TestServerIntegration:
    async def test_render_masks_response_when_active(self, tmp_path: Any) -> None:
        response = Response(
            200,
            json.dumps({"_source": {"source": {"ip": "10.0.0.9"}}}),
            "https://indexer.example/x",
        )
        previous = server._anonymizer
        server._anonymizer = Anonymizer(
            AnonymizationConfig(enabled=True, log_path=str(tmp_path / "llm_prompts.log"))
        )
        try:
            out = server._render("search", [], response)
            assert "10.0.0.9" not in out
            assert "[IP_" in out
        finally:
            server._anonymizer = previous

    async def test_render_unchanged_when_inactive(self) -> None:
        response = Response(
            200,
            json.dumps({"_source": {"source": {"ip": "10.0.0.9"}}}),
            "https://indexer.example/x",
        )
        previous = server._anonymizer
        server._anonymizer = Anonymizer(AnonymizationConfig(enabled=False))
        try:
            out = server._render("search", [], response)
            assert "10.0.0.9" in out
        finally:
            server._anonymizer = previous

    async def test_search_tool_uses_the_guard(
        self, indexer: RecordingIndexer, active_server: None
    ) -> None:
        from klaxon_mcp.server import search

        indexer.payload = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        "_source": {
                            "user": {"name": "admin"},
                            "source": {"ip": "192.168.1.100"},
                        }
                    }
                ],
            }
        }
        out = await search(index="wazuh-events-v5-*", body='{"size": 1}')
        assert "admin" not in out
        assert "192.168.1.100" not in out
        assert "[USER_" in out
        assert "[IP_" in out

    async def test_search_tool_untouched_when_inactive(
        self, indexer: RecordingIndexer
    ) -> None:
        from klaxon_mcp.server import search

        indexer.payload = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        "_source": {
                            "user": {"name": "admin"},
                            "source": {"ip": "192.168.1.100"},
                        }
                    }
                ],
            }
        }
        out = await search(index="wazuh-events-v5-*", body='{"size": 1}')
        assert "admin" in out
        assert "192.168.1.100" in out
