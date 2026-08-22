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
    drop_unmappable_aggs,
    drop_unmappable_features,
    find_unmappable_aggs,
    find_unmappable_features,
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

    def test_whitespace_padded_value_maps_to_stripped_token(self) -> None:
        """L4: a whole value with surrounding whitespace must yield the same
        token as the stripped value — same logical value, same token."""
        a = anon()
        assert a.mask_json({"custom.peer": " 10.0.0.1 "})["custom.peer"] == ip_ph("10.0.0.1")
        assert a.mask_json({"custom.peer": "10.0.0.1"})["custom.peer"] == a.mask_json(
            {"custom.peer": " 10.0.0.1 "}
        )["custom.peer"]


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

    def test_export_keeps_masked_line_whose_body_contains_raw_marker(
        self, tmp_path: Any
    ) -> None:
        """L7: the RAW marker inside a MASKED body is not a raw line."""
        log = str(tmp_path / "llm_prompts.log")
        with open(log, "w", encoding="utf-8") as fh:
            fh.write('ts - [EXTERNAL_LLM] - search MASKED: {"msg": "RAW: not really"}\n')
        exported = Anonymizer.export_masked_log(log)
        assert '{"msg": "RAW: not really"}' in exported
        assert "RAW:" in exported


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

    def test_nested_sub_aggregations_direct_siblings_masked(self) -> None:
        """OpenSearch nests sub-aggregations DIRECTLY in the bucket — siblings of
        `key`/`doc_count`, with no `aggregations` wrapper. The walker must
        tokenise keys at EVERY level, not just the top one. This is the exact
        regression: `terms related.hosts -> terms related.user` left the nested
        `related.user` keys RAW."""
        body = {
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {
                        "users": {"terms": {"field": "related.user"}},
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "hosts": {
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 1,
                    "buckets": [
                        {
                            "key": "nc02web",
                            "doc_count": 3,
                            "users": {
                                "buckets": [
                                    {"key": "root", "doc_count": 2},
                                    {"key": "podomoro", "doc_count": 1},
                                ]
                            },
                        },
                        {
                            "key": "yun",
                            "doc_count": 2,
                            "users": {"buckets": [{"key": "root", "doc_count": 2}]},
                        },
                    ],
                }
            }
        }
        masked, _ = self.mask(response, body)
        hosts = masked["aggregations"]["hosts"]["buckets"]
        assert hosts[0]["key"] == ph("HOST", "nc02web")
        assert hosts[1]["key"] == ph("HOST", "yun")
        # Nested sub-agg keys tokenised at depth (the bug: they came back RAW).
        assert [u["key"] for u in hosts[0]["users"]["buckets"]] == [
            ph("USER", "root"),
            ph("USER", "podomoro"),
        ]
        assert [u["key"] for u in hosts[1]["users"]["buckets"]] == [
            ph("USER", "root")
        ]
        # Counts untouched at every level, incl. agg-level metadata.
        assert [u["doc_count"] for u in hosts[0]["users"]["buckets"]] == [2, 1]
        assert hosts[0]["doc_count"] == 3
        assert hosts[1]["doc_count"] == 2
        assert masked["aggregations"]["hosts"]["doc_count_error_upper_bound"] == 0
        assert masked["aggregations"]["hosts"]["sum_other_doc_count"] == 1

    def test_nested_unmasked_sub_aggregation_keys_stay_raw(self) -> None:
        """agents -> categories (real OpenSearch shape, direct siblings): the top
        key is a mask field (`wazuh.agent.name`), the nested `category` key is
        not (`wazuh.integration.category`). A nested key of an UNMASKED field
        must stay readable — the walker never guesses."""
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
                            "categories": {
                                "buckets": [
                                    {"key": "cloud-services", "doc_count": 2},
                                    {"key": "security", "doc_count": 1},
                                ]
                            },
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        agents = masked["aggregations"]["agents"]["buckets"]
        assert agents[0]["key"] == ph("HOST", "web-server-01")
        assert [c["key"] for c in agents[0]["categories"]["buckets"]] == [
            "cloud-services",
            "security",
        ]

    def test_nested_sub_aggregations_wrapper_shape_still_walked(self) -> None:
        """Some proxies still nest sub-aggregations under an `aggregations`
        wrapper inside the bucket; that legacy shape keeps working."""
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

    def test_deeply_nested_sub_aggregations_masked_at_every_depth(self) -> None:
        """Recursion must be depth-agnostic: three nested levels, each with a
        different masked field, all tokenised."""
        body = {
            "aggs": {
                "l1": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {
                        "l2": {
                            "terms": {"field": "user.name"},
                            "aggs": {
                                "l3": {"terms": {"field": "source.ip"}},
                            },
                        }
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "l1": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "doc_count": 1,
                            "l2": {
                                "buckets": [
                                    {
                                        "key": "root",
                                        "doc_count": 1,
                                        "l3": {
                                            "buckets": [
                                                {"key": "10.0.0.1", "doc_count": 1}
                                            ]
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        l1 = masked["aggregations"]["l1"]["buckets"][0]
        assert l1["key"] == ph("HOST", "nc02web")
        l2 = l1["l2"]["buckets"][0]
        assert l2["key"] == ph("USER", "root")
        l3 = l2["l3"]["buckets"][0]
        assert l3["key"] == ph("IP", "10.0.0.1")

    def test_same_sub_agg_name_under_different_parents_resolves_per_level(
        self,
    ) -> None:
        """Agg-name collisions across parents: both parents declare a sub-agg
        named `users`, but on DIFFERENT fields. The walker must use the field of
        the level it is at — the flat name map would pick one spec for both."""
        body = {
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {"users": {"terms": {"field": "related.user"}}},
                },
                "agents": {
                    "terms": {"field": "wazuh.agent.name"},
                    "aggs": {"users": {"terms": {"field": "related.hosts"}}},
                },
            }
        }
        response = {
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "doc_count": 1,
                            "users": {"buckets": [{"key": "root", "doc_count": 1}]},
                        }
                    ]
                },
                "agents": {
                    "buckets": [
                        {
                            "key": "web-01",
                            "doc_count": 1,
                            "users": {"buckets": [{"key": "host-c", "doc_count": 1}]},
                        }
                    ]
                },
            }
        }
        masked, _ = self.mask(response, body)
        hosts_users = masked["aggregations"]["hosts"]["buckets"][0]["users"]["buckets"]
        agents_users = (
            masked["aggregations"]["agents"]["buckets"][0]["users"]["buckets"]
        )
        assert hosts_users[0]["key"] == ph("USER", "root")  # related.user -> USER
        assert agents_users[0]["key"] == ph("HOST", "host-c")  # related.hosts -> HOST

    def test_named_filters_bucket_nested_sub_agg_masked(self) -> None:
        """A keyed aggregation (`filters`) with a nested terms on a masked field:
        the filter name stays a readable label, the nested bucket keys are
        tokenised."""
        body = {
            "aggs": {
                "f": {
                    "filters": {
                        "filters": {"admin-logins": {"match_all": {}}},
                    },
                    "aggs": {
                        "users": {"terms": {"field": "user.name"}},
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "f": {
                    "buckets": {
                        "admin-logins": {
                            "doc_count": 2,
                            "users": {"buckets": [{"key": "root", "doc_count": 2}]},
                        }
                    }
                }
            }
        }
        masked, _ = self.mask(response, body)
        buckets = masked["aggregations"]["f"]["buckets"]
        assert list(buckets.keys()) == ["admin-logins"]
        assert buckets["admin-logins"]["doc_count"] == 2
        assert [u["key"] for u in buckets["admin-logins"]["users"]["buckets"]] == [
            ph("USER", "root")
        ]

    def test_nested_composite_masks_key_and_after_key(self) -> None:
        """A composite sub-aggregation: its `key` AND `after_key` are tokenised
        with the same tokens, so pagination through the nested composite stays
        consistent."""
        body = {
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {
                        "comp": {
                            "composite": {
                                "sources": [
                                    {"host": {"terms": {"field": "related.hosts"}}},
                                    {"user": {"terms": {"field": "user.name"}}},
                                ]
                            }
                        }
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "doc_count": 1,
                            "comp": {
                                "after_key": {"host": "nc02web", "user": "root"},
                                "buckets": [
                                    {
                                        "key": {"host": "nc02web", "user": "root"},
                                        "doc_count": 1,
                                    }
                                ],
                            },
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        comp = masked["aggregations"]["hosts"]["buckets"][0]["comp"]
        assert comp["after_key"] == {
            "host": ph("HOST", "nc02web"),
            "user": ph("USER", "root"),
        }
        assert comp["buckets"][0]["key"] == {
            "host": ph("HOST", "nc02web"),
            "user": ph("USER", "root"),
        }

    def test_nested_multi_terms_masks_only_masked_element(self) -> None:
        """A nested `multi_terms`: each key array element is masked only when its
        aligned source field is in `mask_fields`."""
        body = {
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {
                        "pairs": {
                            "multi_terms": {
                                "terms": [
                                    {"field": "user.name"},
                                    {"field": "wazuh.integration.category"},
                                ]
                            }
                        }
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "doc_count": 1,
                            "pairs": {
                                "buckets": [
                                    {
                                        "key": ["root", "cloud-services"],
                                        "doc_count": 3,
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        pairs = masked["aggregations"]["hosts"]["buckets"][0]["pairs"]
        assert pairs["buckets"][0]["key"] == [ph("USER", "root"), "cloud-services"]

    def test_nested_top_hits_embedded_source_masked(self) -> None:
        """top_hits nested inside a bucket: the embedded `_source` runs through
        the normal document-masking path at any depth."""
        body = {
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {
                        "top": {"top_hits": {"size": 1}},
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "doc_count": 1,
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
                            },
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        top = masked["aggregations"]["hosts"]["buckets"][0]["top"]
        src = top["hits"]["hits"][0]["_source"]
        assert src["user"]["name"] == ph("USER", "admin")
        assert src["source"]["ip"] == ph("IP", "10.0.0.9")

    def test_nested_sub_agg_already_tokenized_passes_through(self) -> None:
        """Masked-stream idempotency at depth: sub-agg keys that are ALREADY
        tokens (ingest-masked stream) pass through unchanged, no double-masking."""
        body = {
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {
                        "users": {"terms": {"field": "related.user"}},
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {
                            "key": "[HOST_aaaaaaaaaaaaaaaa]",
                            "doc_count": 1,
                            "users": {
                                "buckets": [
                                    {"key": "[USER_bbbbbbbbbbbbbbbb]", "doc_count": 1}
                                ]
                            },
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        hosts = masked["aggregations"]["hosts"]["buckets"][0]
        assert hosts["key"] == "[HOST_aaaaaaaaaaaaaaaa]"
        assert hosts["users"]["buckets"][0]["key"] == "[USER_bbbbbbbbbbbbbbbb]"

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

    def test_multi_terms_key_as_string_rebuilt_from_masked_key(self) -> None:
        """multi_terms on a masked + an unmasked field: key_as_string is REBUILT
        from the masked key list — the leak (a raw hostname inside
        key_as_string) is gone, and key_as_string == "|".join(key)."""
        body = {
            "aggs": {
                "pairs": {
                    "multi_terms": {
                        "terms": [
                            {"field": "related.hosts"},
                            {"field": "wazuh.integration.category"},
                        ]
                    }
                }
            }
        }
        response = {
            "aggregations": {
                "pairs": {
                    "buckets": [
                        {
                            "key": ["brummfidel.sec73.io", "system-activity"],
                            "key_as_string": "brummfidel.sec73.io|system-activity",
                            "doc_count": 3,
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        bucket = masked["aggregations"]["pairs"]["buckets"][0]
        assert bucket["key"] == [ph("HOST", "brummfidel.sec73.io"), "system-activity"]
        assert bucket["key_as_string"] == "|".join(bucket["key"])
        assert "brummfidel.sec73.io" not in bucket["key_as_string"]

    def test_multi_terms_key_as_string_same_family_for_ip(self) -> None:
        """An IP-valued masked field in multi_terms: key and key_as_string use
        the SAME family (no [IP_] inside key_as_string when key is [HOST_])."""
        body = {
            "aggs": {
                "pairs": {
                    "multi_terms": {
                        "terms": [
                            {"field": "related.hosts"},
                            {"field": "wazuh.integration.category"},
                        ]
                    }
                }
            }
        }
        response = {
            "aggregations": {
                "pairs": {
                    "buckets": [
                        {
                            "key": ["10.0.0.1", "system-activity"],
                            "key_as_string": "10.0.0.1|system-activity",
                            "doc_count": 3,
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        bucket = masked["aggregations"]["pairs"]["buckets"][0]
        # related.hosts -> HOST family, not the IP pass.
        assert bucket["key"][0] == ph("HOST", "10.0.0.1")
        assert bucket["key_as_string"].startswith("[HOST_")
        assert "[IP_" not in bucket["key_as_string"]
        assert bucket["key_as_string"] == "|".join(bucket["key"])

    def test_terms_key_as_string_equals_key_token(self) -> None:
        """terms with key_as_string (e.g. a request `format` that reformats the
        key): key_as_string equals the masked KEY token. Pre-fix the raw
        key_as_string was re-tokenised on its own — a DIFFERENT token — so this
        FAILS before the fix and passes after."""
        body = {
            "aggs": {
                "hosts": {"terms": {"field": "related.hosts", "format": "..."}}
            }
        }
        response = {
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "key_as_string": "nc02web (formatted)",
                            "doc_count": 5,
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        bucket = masked["aggregations"]["hosts"]["buckets"][0]
        assert bucket["key"] == ph("HOST", "nc02web")
        assert bucket["key_as_string"] == ph("HOST", "nc02web")

    def test_terms_unmasked_field_key_as_string_untouched(self) -> None:
        """An unmasked terms field with a formatted key_as_string (e.g. a date):
        both key and key_as_string stay untouched — the formatted value is not
        replaced by the raw key."""
        body = {
            "aggs": {"t": {"terms": {"field": "@timestamp"}}}
        }
        response = {
            "aggregations": {
                "t": {
                    "buckets": [
                        {
                            "key": 1754697600000,
                            "key_as_string": "2026-08-09T00:00:00.000Z",
                            "doc_count": 4,
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        bucket = masked["aggregations"]["t"]["buckets"][0]
        assert bucket["key"] == 1754697600000
        assert bucket["key_as_string"] == "2026-08-09T00:00:00.000Z"

    def test_multi_terms_already_tokenized_passes_through(self) -> None:
        """Masked-stream shape: multi_terms keys are already tokens, so the
        rebuilt key_as_string (joined from the unchanged keys) is identical —
        no double-masking."""
        body = {
            "aggs": {
                "pairs": {
                    "multi_terms": {
                        "terms": [
                            {"field": "related.hosts"},
                            {"field": "wazuh.integration.category"},
                        ]
                    }
                }
            }
        }
        response = {
            "aggregations": {
                "pairs": {
                    "buckets": [
                        {
                            "key": ["[HOST_aaaaaaaaaaaaaaaa]", "system-activity"],
                            "key_as_string": "[HOST_aaaaaaaaaaaaaaaa]|system-activity",
                            "doc_count": 3,
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        bucket = masked["aggregations"]["pairs"]["buckets"][0]
        assert bucket["key"] == ["[HOST_aaaaaaaaaaaaaaaa]", "system-activity"]
        assert bucket["key_as_string"] == "[HOST_aaaaaaaaaaaaaaaa]|system-activity"

    def test_nested_multi_terms_key_as_string_rebuilt(self) -> None:
        """The key_as_string fix also applies at depth (Teil-11 walker): a
        nested multi_terms key_as_string is rebuilt from its masked key list."""
        body = {
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {
                        "pairs": {
                            "multi_terms": {
                                "terms": [
                                    {"field": "related.user"},
                                    {"field": "wazuh.integration.category"},
                                ]
                            }
                        }
                    },
                }
            }
        }
        response = {
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "doc_count": 1,
                            "pairs": {
                                "buckets": [
                                    {
                                        "key": ["root", "system-activity"],
                                        "key_as_string": "root|system-activity",
                                        "doc_count": 3,
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        }
        masked, _ = self.mask(response, body)
        bucket = masked["aggregations"]["hosts"]["buckets"][0]["pairs"]["buckets"][0]
        assert bucket["key"] == [ph("USER", "root"), "system-activity"]
        assert bucket["key_as_string"] == "|".join(bucket["key"])
        assert "root" not in bucket["key_as_string"]

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

    def test_nested_specs_carry_children_hierarchy(self) -> None:
        """Each AggSpec records its own sub-aggregations, so the response walker
        can descend through buckets and resolve per-level fields (name collisions
        across parents are resolved, not merged into one flat entry)."""
        specs = parse_agg_fields(
            {
                "aggs": {
                    "hosts": {
                        "terms": {"field": "related.hosts"},
                        "aggs": {
                            "users": {"terms": {"field": "related.user"}}
                        },
                    }
                }
            }
        )
        hosts = specs["hosts"]
        users = hosts.child("users")
        assert users is not None
        assert users.agg_type == "terms"
        assert users.fields == ("related.user",)
        assert hosts.child("unknown") is None
        # The flat map still records the nested name for compatibility.
        assert specs["users"].fields == ("related.user",)
        # A sub-agg with no children of its own.
        assert users.child("anything") is None

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


# --------------------------------------------------------------------------- #
# Teil 12.3 — fail-closed gate on unmappable aggregations + deep value pass
# --------------------------------------------------------------------------- #


class TestFindUnmappableAggs:
    """Request-side detection of aggregation types the walker cannot map.

    `scripted_metric` (and any unknown/unhandled type) is served with an OPAQUE
    output the response walker cannot map — its script can read ANY field and
    the values reach the consumer RAW. `find_unmappable_aggs` detects them so
    `server.search` can reject (default) or drop the request.
    """

    def test_scripted_metric_top_level_detected(self) -> None:
        body = {
            "size": 0,
            "aggs": {
                "scripted": {
                    "scripted_metric": {
                        "init_script": "x",
                        "map_script": "y",
                        "combine_script": "z",
                    }
                }
            },
        }
        assert find_unmappable_aggs(body) == [("scripted", "scripted_metric")]

    def test_unknown_agg_type_detected(self) -> None:
        body = {"size": 0, "aggs": {"weird": {"weird_agg": {"x": 1}}}}
        assert find_unmappable_aggs(body) == [("weird", "weird_agg")]

    def test_nested_scripted_metric_reports_top_level_name(self) -> None:
        """An opaque sub-agg under a safe parent is reported with the TOP-LEVEL
        name, so a drop can remove the whole offending subtree."""
        body = {
            "size": 0,
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {"sm": {"scripted_metric": {"map_script": "x"}}},
                }
            },
        }
        assert find_unmappable_aggs(body) == [("hosts", "scripted_metric")]

    def test_multiple_unmappable_reported_in_order(self) -> None:
        body = {
            "size": 0,
            "aggs": {
                "a": {"scripted_metric": {"map_script": "x"}},
                "b": {"unknown_thing": {}},
                "a2": {"scripted_metric": {"map_script": "x"}},
            },
        }
        assert find_unmappable_aggs(body) == [
            ("a", "scripted_metric"),
            ("b", "unknown_thing"),
            ("a2", "scripted_metric"),
        ]

    def test_safe_aggs_not_detected(self) -> None:
        body = {
            "size": 0,
            "aggs": {
                "hosts": {"terms": {"field": "related.hosts"}},
                "sig": {"significant_terms": {"field": "user.name"}},
                "multi": {
                    "multi_terms": {
                        "terms": [
                            {"field": "related.hosts"},
                            {"field": "user.name"},
                        ]
                    }
                },
                "comp": {
                    "composite": {
                        "sources": [
                            {"h": {"terms": {"field": "related.hosts"}}}
                        ]
                    }
                },
                "th": {"top_hits": {"size": 1}},
                "dates": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "day",
                    }
                },
                "hist": {"histogram": {"field": "bytes", "interval": 100}},
                "rng": {"range": {"field": "bytes", "ranges": [{"to": 100}]}},
                "f": {"filters": {"filters": {"a": {"match_all": {}}}}},
                "avg": {"avg": {"field": "bytes"}},
                "card": {"cardinality": {"field": "user.name"}},
                "nested_safe": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {"users": {"terms": {"field": "related.user"}}},
                },
            },
        }
        assert find_unmappable_aggs(body) == []

    def test_aggs_and_meta_keys_are_not_agg_types(self) -> None:
        body = {
            "size": 0,
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "meta": {"label": "hosts"},
                }
            },
        }
        assert find_unmappable_aggs(body) == []

    def test_non_dict_body_is_empty(self) -> None:
        assert find_unmappable_aggs(None) == []
        assert find_unmappable_aggs({"query": {"match_all": {}}}) == []
        assert find_unmappable_aggs({"aggs": "nope"}) == []

    def test_opaque_flag_on_parsed_specs(self) -> None:
        """The parsed spec carries the opaque flag so the walker can serve an
        opaque aggregation through the deep value pass."""
        specs = parse_agg_fields(
            {"aggs": {"sm": {"scripted_metric": {"map_script": "x"}}}}
        )
        assert specs["sm"].opaque is True
        specs = parse_agg_fields(
            {"aggs": {"f": {"filters": {"filters": {}}}}}
        )
        assert specs["f"].opaque is False
        specs = parse_agg_fields(
            {"aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        assert specs["hosts"].opaque is False

    def test_drop_removes_offending_top_level(self) -> None:
        body = {
            "size": 0,
            "aggs": {
                "hosts": {"terms": {"field": "related.hosts"}},
                "scripted": {"scripted_metric": {"map_script": "x"}},
            },
        }
        dropped = drop_unmappable_aggs(body, {"scripted"})
        assert dropped["aggs"] == {"hosts": {"terms": {"field": "related.hosts"}}}
        # The original is not mutated.
        assert "scripted" in body["aggs"]

    def test_drop_removes_nested_offending_subtree(self) -> None:
        body = {
            "size": 0,
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {"sm": {"scripted_metric": {"map_script": "x"}}},
                }
            },
        }
        dropped = drop_unmappable_aggs(body, {"hosts"})
        assert dropped["aggs"] == {}

    def test_drop_unknown_name_is_noop(self) -> None:
        body = {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        assert drop_unmappable_aggs(body, {"nope"})["aggs"] == body["aggs"]


class TestFindUnmappableFeatures:
    """Teil 13: request features whose response output the walker cannot map.

    `runtime_mappings` (a runtime field can copy a masked field under a NEW name
    and be aggregated on), `script_fields` (arbitrary code, like
    scripted_metric), `suggest` (returns raw field text) and `highlight`
    (snippets embed raw source text) are opaque to the response walker.
    `find_unmappable_features` detects them so `server.search` can reject
    (default) or drop the request.
    """

    def test_all_four_features_detected(self) -> None:
        body = {
            "runtime_mappings": {"rt": {}},
            "script_fields": {"who": {}},
            "suggest": {"u": {}},
            "highlight": {"fields": {}},
            "size": 0,
        }
        assert find_unmappable_features(body) == [
            ("runtime_mappings", "runtime_mappings"),
            ("script_fields", "script_fields"),
            ("suggest", "suggest"),
            ("highlight", "highlight"),
        ]

    def test_single_feature_detected(self) -> None:
        assert find_unmappable_features({"script_fields": {"who": {}}}) == [
            ("script_fields", "script_fields")
        ]

    def test_clean_body_is_empty(self) -> None:
        assert find_unmappable_features(None) == []
        assert find_unmappable_features({"size": 0}) == []
        assert find_unmappable_features({"query": {"match_all": {}}}) == []
        assert find_unmappable_features(
            {"aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        ) == []

    def test_drop_removes_the_features(self) -> None:
        body = {
            "script_fields": {"who": {}},
            "highlight": {"fields": {}},
            "size": 0,
            "aggs": {"hosts": {"terms": {"field": "related.hosts"}}},
        }
        dropped = drop_unmappable_features(body, {"script_fields", "highlight"})
        assert dropped == {
            "size": 0,
            "aggs": {"hosts": {"terms": {"field": "related.hosts"}}},
        }
        # The original is not mutated.
        assert "script_fields" in body
        assert "highlight" in body


class TestRareTermsAggregationMasking:
    """Teil 13: rare_terms is a field-mapped family like terms — its key AND
    key_as_string must be tokenised (was blocked as unmappable; mapping it is
    the checklist requirement)."""

    def test_rare_terms_key_and_key_as_string_masked(self) -> None:
        a = anon(mask_aggregation_keys=True, mask_fields=MASK_FIELDS_18)
        request = {
            "size": 0,
            "aggs": {"rares": {"rare_terms": {"field": "related.hosts"}}},
        }
        response_body = {
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
            "aggregations": {
                "rares": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "key_as_string": "nc02web",
                            "doc_count": 3,
                        }
                    ]
                }
            },
        }
        masked = a.mask_response(
            Response(200, json.dumps(response_body), "https://x"),
            agg_map=parse_agg_fields(request),
        ).json()
        bucket = masked["aggregations"]["rares"]["buckets"][0]
        assert bucket["key"] == ph("HOST", "nc02web")
        assert bucket["key_as_string"] == ph("HOST", "nc02web")
        assert "nc02web" not in json.dumps(masked)

    def test_rare_terms_parsed_as_mapped_family(self) -> None:
        specs = parse_agg_fields(
            {"aggs": {"rares": {"rare_terms": {"field": "user.name"}}}}
        )
        assert specs["rares"].agg_type == "rare_terms"
        assert specs["rares"].fields == ("user.name",)
        assert specs["rares"].opaque is False


class TestDeepValuePass:
    """Defense-in-depth: opaque aggregation outputs are masked by VALUE.

    A `scripted_metric` (or any opaque container) can emit ANY field value its
    script read. The deep value pass masks those string leaves by value pattern
    (e-mail, IP, FQDN hostname, UUID) and by the response's known-value registry
    (so a raw hostname/username in the opaque output reuses the exact `_source`
    token). Existing tokens pass through unchanged (idempotent); non-personal
    free text (category labels) is untouched.
    """

    def deep_anon(self, **overrides: Any) -> Anonymizer:
        return anon(
            mask_aggregation_keys=True,
            mask_fields=MASK_FIELDS_18,
            **overrides,
        )

    def mask(self, response_body: Any, request_body: Any) -> tuple[Any, Anonymizer]:
        a = self.deep_anon()
        response = Response(
            200, json.dumps(response_body), "https://indexer.example/_search"
        )
        masked = a.mask_response(response, agg_map=parse_agg_fields(request_body))
        return masked.json(), a

    OPAQUE_BODY = {"size": 0, "aggs": {"scripted": {"scripted_metric": {"map_script": "x"}}}}

    def _opaque_response(self, value: list[str]) -> dict[str, Any]:
        return {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        "_source": {
                            "wazuh": {
                                "agent": {"host": {"hostname": "Supergrobi.intern.moenig.it"}}
                            },
                            "related": {"user": ["root", "marco"]},
                            "user": {"id": "e883b765-27d5-44f5-89ba-209a31ae3b89"},
                        }
                    }
                ],
            },
            "aggregations": {"scripted": {"value": value}},
        }

    def test_opaque_output_masks_hostname_username_ip_uuid(self) -> None:
        masked, _ = self.mask(
            self._opaque_response(
                [
                    "Supergrobi.intern.moenig.it",
                    "root",
                    "marco",
                    "e883b765-27d5-44f5-89ba-209a31ae3b89",
                    "192.168.1.10",
                ]
            ),
            self.OPAQUE_BODY,
        )
        value = masked["aggregations"]["scripted"]["value"]
        # The opaque echoes reuse the EXACT `_source` token (one entity -> one
        # token everywhere), and the IP/UUID are masked by value pattern.
        assert value[0] == ph("HOST", "Supergrobi.intern.moenig.it")
        assert value[1] == ph("USER", "root")
        assert value[2] == ph("USER", "marco")
        assert value[3] == ph("USER", "e883b765-27d5-44f5-89ba-209a31ae3b89")
        assert value[4] == ph("IP", "192.168.1.10")
        # No raw value anywhere.
        for raw in (
            "Supergrobi.intern.moenig.it",
            "root",
            "marco",
            "e883b765-27d5-44f5-89ba-209a31ae3b89",
            "192.168.1.10",
        ):
            assert raw not in json.dumps(value)

    def test_opaque_output_without_source_masks_by_pattern(self) -> None:
        """No `_source` docs (size 0): the FQDN/UUID/IP are still masked by
        value pattern; a bare username is NOT guessed at without an identity."""
        body = {
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
            "aggregations": {
                "scripted": {
                    "value": [
                        "Supergrobi.intern.moenig.it",
                        "e883b765-27d5-44f5-89ba-209a31ae3b89",
                        "192.168.1.10",
                        "system-activity",
                    ]
                }
            },
        }
        masked, _ = self.mask(body, self.OPAQUE_BODY)
        value = masked["aggregations"]["scripted"]["value"]
        assert value[0] == ph("HOST", "Supergrobi.intern.moenig.it")
        assert value[1] == ph("USER", "e883b765-27d5-44f5-89ba-209a31ae3b89")
        assert value[2] == ph("IP", "192.168.1.10")
        assert value[3] == "system-activity"

    def test_existing_tokens_pass_through_idempotent(self) -> None:
        masked, _ = self.mask(
            self._opaque_response(["[HOST_aaaaaaaaaaaaaaaa]", "[USER_bbbbbbbbbbbbbbbb]"]),
            self.OPAQUE_BODY,
        )
        value = masked["aggregations"]["scripted"]["value"]
        assert value == ["[HOST_aaaaaaaaaaaaaaaa]", "[USER_bbbbbbbbbbbbbbbb]"]

    def test_unmasked_free_text_category_untouched(self) -> None:
        masked, _ = self.mask(
            self._opaque_response(["system-activity", "cloud-services", "security"]),
            self.OPAQUE_BODY,
        )
        value = masked["aggregations"]["scripted"]["value"]
        assert value == ["system-activity", "cloud-services", "security"]

    def test_opaque_output_is_deterministic_across_runs(self) -> None:
        a = self.deep_anon()
        response = Response(
            200, json.dumps(self._opaque_response(["root", "marco"])),
            "https://indexer.example/_search",
        )
        first = a.mask_response(
            response, agg_map=parse_agg_fields(self.OPAQUE_BODY)
        ).json()
        second = a.mask_response(
            response, agg_map=parse_agg_fields(self.OPAQUE_BODY)
        ).json()
        assert first == second

    def test_nested_opaque_sub_agg_is_masked(self) -> None:
        """An opaque sub-aggregation nested inside a mapped bucket (siblings of
        key/doc_count) is served through the deep value pass too."""
        response = {
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
            "aggregations": {
                "hosts": {
                    "buckets": [
                        {
                            "key": "nc02web",
                            "doc_count": 1,
                            "sm": {"value": ["Supergrobi.intern.moenig.it", "system-activity"]},
                        }
                    ]
                }
            },
        }
        request = {
            "size": 0,
            "aggs": {
                "hosts": {
                    "terms": {"field": "related.hosts"},
                    "aggs": {"sm": {"scripted_metric": {"map_script": "x"}}},
                }
            },
        }
        masked, _ = self.mask(response, request)
        sm = masked["aggregations"]["hosts"]["buckets"][0]["sm"]["value"]
        assert sm[0] == ph("HOST", "Supergrobi.intern.moenig.it")
        assert sm[1] == "system-activity"

    def test_mapped_agg_keys_not_touched_by_deep_pass(self) -> None:
        """The deep pass only serves OPAQUE aggregations: a terms key on an
        unmasked field stays raw even when it echoes a `_source` value (the
        structured walker owns mapped keys — no behaviour change)."""
        response = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [{"_source": {"user": {"name": "alice"}}}],
            },
            "aggregations": {
                "top_users": {
                    "buckets": [{"key": "alice", "doc_count": 10}]
                }
            },
        }
        request = {
            "size": 0,
            "aggs": {"top_users": {"terms": {"field": "wazuh.integration.category"}}},
        }
        masked, _ = self.mask(response, request)
        assert masked["aggregations"]["top_users"]["buckets"][0]["key"] == "alice"


class TestOpaqueResponseSubtrees:
    """Teil 13: `suggest` (top-level), `highlight` and `fields` (per hit) embed
    source text under arbitrary key names the structured walker cannot map.
    They are served through the deep value pass — the request gate blocks them
    by default; this is the defense-in-depth net for the explicit "off" mode."""

    def deep_anon(self, **overrides: Any) -> Anonymizer:
        return anon(
            mask_aggregation_keys=True,
            mask_fields=MASK_FIELDS_18,
            **overrides,
        )

    def _doc(self) -> dict[str, Any]:
        return {
            "_source": {
                "user": {"name": "marco"},
                "host": {"hostname": "nc02web.intern.example"},
                "related": {"user": ["root"]},
            }
        }

    def test_fields_script_field_alias_masked_via_doc_registry(self) -> None:
        """A script_fields alias (`who`) echoes `user.name`; the deep value pass
        reuses the DOCUMENT's exact `_source` token (the exact Teil-13 finding:
        raw value under an unmapped key name)."""
        body = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        **self._doc(),
                        "fields": {
                            "who": ["marco"],
                            "host.hostname": ["nc02web.intern.example"],
                        },
                    }
                ],
            }
        }
        a = self.deep_anon()
        masked = a.mask_response(Response(200, json.dumps(body), "https://x")).json()
        fields = masked["hits"]["hits"][0]["fields"]
        assert fields["who"] == [ph("USER", "marco")]
        assert fields["host.hostname"] == [ph("HOST", "nc02web.intern.example")]
        assert "marco" not in json.dumps(masked)
        assert "nc02web.intern.example" not in json.dumps(masked)

    def test_highlight_bare_username_in_snippet_masked(self) -> None:
        """Highlight tags break the username context patterns; the per-document
        registry catches the bare username by word boundary."""
        body = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        **self._doc(),
                        "highlight": {
                            "user.name": ["<em>marco</em>"],
                            "message": ["login as <em>marco</em> then more"],
                        },
                    }
                ],
            }
        }
        a = self.deep_anon()
        masked = a.mask_response(Response(200, json.dumps(body), "https://x")).json()
        highlight = masked["hits"]["hits"][0]["highlight"]
        joined = json.dumps(highlight)
        assert "marco" not in joined
        assert ph("USER", "marco") in joined
        # The structured field value keeps its own exact token.
        assert masked["hits"]["hits"][0]["_source"]["user"]["name"] == ph("USER", "marco")

    def test_suggest_uses_response_wide_registry(self) -> None:
        """A term/completion suggester returns raw field text; the response-wide
        registry (from the raw `_source` docs) reuses the exact tokens."""
        body = {
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [self._doc()]},
            "suggest": {
                "u": [
                    {
                        "text": "marco",
                        "offset": 0,
                        "length": 5,
                        "options": [{"text": "root", "score": 1.0}],
                    }
                ]
            },
        }
        a = self.deep_anon()
        masked = a.mask_response(Response(200, json.dumps(body), "https://x")).json()
        sug = masked["suggest"]["u"][0]
        assert sug["text"] == ph("USER", "marco")
        assert sug["options"][0]["text"] == ph("USER", "root")
        assert "marco" not in json.dumps(masked["suggest"])

    def test_existing_tokens_in_subtrees_pass_through_idempotent(self) -> None:
        body = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        **self._doc(),
                        "fields": {"who": ["[USER_aaaaaaaaaaaaaaaa]"]},
                        "highlight": {"message": ["user [USER_aaaaaaaaaaaaaaaa]"]},
                    }
                ],
            }
        }
        a = self.deep_anon()
        masked = a.mask_response(Response(200, json.dumps(body), "https://x")).json()
        hit = masked["hits"]["hits"][0]
        assert hit["fields"]["who"] == ["[USER_aaaaaaaaaaaaaaaa]"]
        assert "[USER_aaaaaaaaaaaaaaaa]" in hit["highlight"]["message"][0]


class TestShardFailuresStripped:
    """Teil 13: a 200 response can carry a failed shard whose body echoes the
    raw query (script source, field names, values). Fail-closed: the raw
    `failures` array is stripped from masked output; the count stays."""

    FAILURES_BODY: dict[str, Any] = {
        "_shards": {
            "total": 8,
            "successful": 7,
            "failed": 1,
            "failures": [
                {
                    "shard": 0,
                    "index": ".ds-wazuh-events-v5-access-management-000001",
                    "reason": {
                        "type": "script_exception",
                        "reason": "runtime error",
                        "script": "params._source.user.name;",
                    },
                }
            ],
        },
        "hits": {"total": {"value": 1, "relation": "eq"}, "hits": []},
    }

    def test_failure_array_stripped_when_active(self) -> None:
        a = anon(mask_aggregation_keys=True, mask_fields=MASK_FIELDS_18)
        masked = a.mask_response(
            Response(200, json.dumps(self.FAILURES_BODY), "https://x")
        ).json()
        assert "failures" not in masked["_shards"]
        assert masked["_shards"]["failed"] == 1
        assert "params._source" not in json.dumps(masked)

    def test_failures_kept_when_inactive(self) -> None:
        a = anon(enabled=False)
        masked = a.mask_response(
            Response(200, json.dumps(self.FAILURES_BODY), "https://x")
        )
        assert masked is not None
        assert "failures" in masked.json()["_shards"]
