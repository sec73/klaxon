# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Field discovery: the mapped-vs-populated distinction (acceptance test T2)."""

from __future__ import annotations

import json
from typing import Any

from klaxon_mcp.clients import Response
from klaxon_mcp.fields import (
    build_exists_aggs,
    parse_exists_aggs,
    parse_field_caps,
)


def caps_response(fields: dict[str, Any], status: int = 200) -> Response:
    return Response(status, json.dumps({"fields": fields}), "https://x/_field_caps")


class TestParseFieldCaps:
    def test_extracts_name_and_type(self) -> None:
        result = parse_field_caps(
            caps_response(
                {
                    "wazuh.agent.id": {"keyword": {"type": "keyword"}},
                    "source.ip": {"ip": {"type": "ip"}},
                    "destination.port": {"long": {"type": "long"}},
                }
            )
        )
        assert result.ok
        assert [(f.name, f.type_label) for f in result.fields] == [
            ("destination.port", "long"),
            ("source.ip", "ip"),
            ("wazuh.agent.id", "keyword"),
        ]

    def test_skips_metadata_fields(self) -> None:
        result = parse_field_caps(
            caps_response(
                {
                    "_index": {"_index": {"type": "_index"}},
                    "_id": {"_id": {"type": "_id"}},
                    "@timestamp": {"date": {"type": "date"}},
                }
            )
        )
        assert [f.name for f in result.fields] == ["@timestamp"]

    def test_marks_type_conflicts(self) -> None:
        result = parse_field_caps(
            caps_response(
                {"rule.id": {"keyword": {"type": "keyword"}, "long": {"type": "long"}}}
            )
        )
        assert result.fields[0].type_label == "CONFLICT:keyword|long"

    def test_error_response_is_not_ok(self) -> None:
        result = parse_field_caps(
            Response(404, json.dumps({"error": {"type": "index_not_found_exception"}}), "u")
        )
        assert not result.ok
        assert result.fields == []

    def test_empty_field_set(self) -> None:
        result = parse_field_caps(caps_response({}))
        assert result.ok
        assert result.fields == []


class TestExistsAggs:
    def test_builds_one_filter_agg_per_field(self) -> None:
        aggs = build_exists_aggs(["agent.id", "wazuh.agent.id"])
        assert aggs == {
            "f0": {"filter": {"exists": {"field": "agent.id"}}},
            "f1": {"filter": {"exists": {"field": "wazuh.agent.id"}}},
        }

    def test_maps_counts_back_onto_names(self) -> None:
        names = ["agent.id", "agent.name", "wazuh.agent.id"]
        response = Response(
            200,
            json.dumps(
                {
                    "aggregations": {
                        "f0": {"doc_count": 0},
                        "f1": {"doc_count": 0},
                        "f2": {"doc_count": 390000},
                    }
                }
            ),
            "u",
        )
        counts = parse_exists_aggs(response, names)
        assert counts == {"agent.id": 0, "agent.name": 0, "wazuh.agent.id": 390000}

    def test_the_agent_id_trap(self) -> None:
        """T2: agent.* is mapped but unpopulated; wazuh.agent.* carries the data.

        Both are keyword in the mapping, so _field_caps alone cannot tell them
        apart — only the exists probe can.
        """
        mapped = parse_field_caps(
            caps_response(
                {
                    "agent.id": {"keyword": {"type": "keyword"}},
                    "agent.name": {"keyword": {"type": "keyword"}},
                    "wazuh.agent.id": {"keyword": {"type": "keyword"}},
                    "wazuh.agent.name": {"keyword": {"type": "keyword"}},
                    "wazuh.agent.version": {"keyword": {"type": "keyword"}},
                }
            )
        )
        # Indistinguishable by type alone.
        assert all(f.type_label == "keyword" for f in mapped.fields)

        names = [f.name for f in mapped.fields]
        probe = Response(
            200,
            json.dumps(
                {
                    "aggregations": {
                        f"f{i}": {"doc_count": 0 if n.startswith("agent.") else 390000}
                        for i, n in enumerate(names)
                    }
                }
            ),
            "u",
        )
        counts = parse_exists_aggs(probe, names)

        populated = sorted(n for n, c in counts.items() if c > 0)
        assert populated == [
            "wazuh.agent.id",
            "wazuh.agent.name",
            "wazuh.agent.version",
        ]
        assert all(counts[n] == 0 for n in names if n.startswith("agent."))

    def test_missing_aggregation_keys_are_omitted(self) -> None:
        response = Response(200, json.dumps({"aggregations": {"f0": {"doc_count": 5}}}), "u")
        assert parse_exists_aggs(response, ["a", "b"]) == {"a": 5}

    def test_non_json_response_yields_no_counts(self) -> None:
        assert parse_exists_aggs(Response(200, "not json", "u"), ["a"]) == {}
