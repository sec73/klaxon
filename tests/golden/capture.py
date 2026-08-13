# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Golden-master capture for the Klaxon modularity refactor.

Deterministic and fully offline: it drives the REAL code paths (the response
layer's `Anonymizer`, the Option B builders and the Python twin, the committed
artifact renderer, and `derive_token`) with fixed inputs and records the exact
output strings. Every refactor commit re-runs this and must produce byte-
identical output — a moved function whose output differs in any byte fails the
refactor.

Not a test: this module only defines the capture. `capture_main.py` writes the
frozen files into `tests/golden/`, `verify.py` re-captures into a temp dir and
diffs, and `test_golden.py` (in `tests/`) wires the diff into `pytest`.
"""

from __future__ import annotations

import json
from pathlib import Path

# Fixed, deterministic salt. Never a real secret — this is a canary for the
# token scheme, not a credential.
GOLDEN_SALT = "golden-master-salt-0123456789abcdef"

# The tenant whose fields.yaml drives the Option B builders. Loading it from
# the real source of truth keeps the capture faithful to the deployment.
TENANT = "customer-a"

GOLDEN_DIR = Path(__file__).resolve().parent


# --------------------------------------------------------------------------- #
# Fixed inputs
# --------------------------------------------------------------------------- #

# A representative forwarded search request whose aggregations have maskable
# source fields (terms, filters-with-dict-buckets, composite with after_key).
REQUEST_BODY = {
    "query": {"bool": {"must": [{"match_all": {}}]}},
    "size": 20,
    "aggs": {
        "top_users": {"terms": {"field": "related.user", "size": 10}},
        "by_host": {
            "filters": {
                "filters": {
                    "host-a": {"term": {"host.hostname": "host-a"}},
                    "host-b": {"term": {"host.hostname": "host-b"}},
                }
            }
        },
        "user_sessions": {
            "composite": {
                "sources": [{"related.user": {"terms": {"field": "related.user"}}}],
                "size": 10,
            }
        },
    },
}

# A representative indexer response: structured fields, arrays, free text with
# usernames/emails/IPs, a whole-value `event.original`, and an IOC
# (`related.hash`) that must stay untouched.
RAW_RESPONSE = {
    "took": 12,
    "hits": {
        "total": {"value": 2, "relation": "eq"},
        "hits": [
            {
                "_index": "wazuh-events-v5-*",
                "_id": "doc1",
                "_source": {
                    "@timestamp": "2026-08-12T10:00:00Z",
                    "user": {
                        "name": "alice",
                        "id": 1001,
                        "effective": {"name": "alice(uid=1001)"},
                    },
                    "source": {
                        "ip": "192.168.1.50",
                        "address": "192.168.1.50",
                        "domain": "internal.example",
                    },
                    "destination": {"ip": "10.20.30.4"},
                    "related": {
                        "user": ["alice", "bob"],
                        "hosts": ["host-a", "host-b"],
                        "hash": ["abc123def456"],
                    },
                    "host": {"hostname": "web-01"},
                    "agent": {"id": "agent-7"},
                    "client": {"user": {"name": "carol"}},
                    "event": {
                        "original": "Aug 12 10:00:01 web-01 sshd[1234]: "
                        "Accepted publickey for alice from 192.168.1.50 "
                        "port 22 ssh2"
                    },
                    "message": (
                        "user alice logged in as alice(uid=1001) from "
                        "192.168.1.50; contact alice@example.com"
                    ),
                    "log": {"logger": "sshd"},
                },
            },
            {
                "_index": "wazuh-events-v5-*",
                "_id": "doc2",
                "_source": {
                    "@timestamp": "2026-08-12T10:05:00Z",
                    "user": {"name": "bob"},
                    "source": {"ip": "172.16.0.7"},
                    "related": {"user": ["bob"], "hosts": ["host-c"]},
                    "event": {
                        "original": "bob@corp.example ran command ls -la"
                    },
                },
            },
        ],
    },
    "aggregations": {
        "top_users": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 5,
            "buckets": [
                {"key": "alice", "doc_count": 10},
                {"key": "bob", "doc_count": 4},
            ],
        },
        "by_host": {
            "buckets": {
                "host-a": {"doc_count": 3},
                "host-b": {"doc_count": 2},
            },
        },
        "user_sessions": {
            "after_key": {"related.user": "carol"},
            "buckets": [
                {"key": {"related.user": "alice"}, "doc_count": 6},
            ],
        },
    },
}

# Token-scheme canary pairs: one per family plus edge cases.
TOKEN_PAIRS = [
    ("USER", "alice"),
    ("USER", "bob"),
    ("IP", "192.168.1.50"),
    ("IP", "10.20.30.4"),
    ("HOST", "web-01"),
    ("HOST", "host-a"),
    ("AGENT", "agent-7"),
    ("USER", ""),
    ("USER", "alice(uid=1001)"),
]


# --------------------------------------------------------------------------- #
# Capture
# --------------------------------------------------------------------------- #


def capture() -> dict[str, str]:
    """relative filename -> exact output content, for one fixed configuration."""
    out: dict[str, str] = {}

    # --- Token scheme (derive_token is the canonical stream token) ---------- #
    from klaxon_mcp.masked_stream import derive_token, token

    tokens = {f"{family}|{value}": derive_token(value, family, GOLDEN_SALT)
              for family, value in TOKEN_PAIRS}
    tokens["token-shape"] = token("USER", "alice", GOLDEN_SALT)
    out["tokens.json"] = json.dumps(tokens, indent=2, sort_keys=True) + "\n"

    # --- Response layer (Anonymizer.mask_response) -------------------------- #
    from klaxon_mcp.anonymization import Anonymizer, parse_agg_fields
    from klaxon_mcp.clients import Response
    from klaxon_mcp.config import AnonymizationConfig

    agg_map = parse_agg_fields(REQUEST_BODY)
    raw_text = json.dumps(RAW_RESPONSE, indent=2, ensure_ascii=False)
    raw_resp = Response(200, raw_text, "http://indexer/wazuh-events-v5-*/_search")

    def mask(free_text_users: bool) -> str:
        anon = Anonymizer(
            AnonymizationConfig(
                enabled=True,
                llm_base_url="https://external.example.com",
                salt=GOLDEN_SALT,
                log_path=str(GOLDEN_DIR / "(no-write)") + "/llm_prompts.log",
                log_raw=False,
                mask_free_text_users=free_text_users,
            )
        )
        return anon.mask_response(raw_resp, agg_map).text

    out["masked-response-freetext.json"] = mask(True)
    out["masked-response-nofreetext.json"] = mask(False)

    # --- Option B Python twin (pipeline_mask_doc) --------------------------- #
    from klaxon_mcp.masked_stream import load_tenant_config, pipeline_mask_doc

    cfg = load_tenant_config(TENANT)
    twin_source = RAW_RESPONSE["hits"]["hits"][0]["_source"]
    out["twin-masked-doc.json"] = (
        json.dumps(
            pipeline_mask_doc(dict(twin_source), cfg, GOLDEN_SALT),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    # --- Option B artifact builders (deployable form, real salt) ------------ #
    from klaxon_mcp.masked_stream import (
        build_config_fragment,
        build_deployable_pipeline,
        build_index_template,
        build_ism_policy,
        build_quarantine_index_template,
        build_quarantine_ism_policy,
        build_roles_fragment,
    )

    # The deployable pipeline is what an operator PUTs to OpenSearch: real salt,
    # NO `_meta` (OpenSearch rejects it) — provenance rides in `description`.
    out["artifacts/pipeline-klaxon-mask-customer-a.json"] = (
        json.dumps(build_deployable_pipeline(cfg, GOLDEN_SALT), indent=2) + "\n"
    )
    out["artifacts/ism-klaxon-masked-retention-customer-a.json"] = (
        json.dumps(build_ism_policy(cfg, 30), indent=2) + "\n"
    )
    out["artifacts/index-template-klaxon-masked-customer-a.json"] = (
        json.dumps(build_index_template(cfg), indent=2) + "\n"
    )
    out["artifacts/klaxon-config.yaml"] = build_config_fragment(cfg)
    # Fail-closed quarantine artifacts (masking-failure routing).
    out["artifacts/ism-klaxon-quarantine-retention-customer-a.json"] = (
        json.dumps(build_quarantine_ism_policy(cfg), indent=2) + "\n"
    )
    out["artifacts/index-template-klaxon-quarantine-customer-a.json"] = (
        json.dumps(build_quarantine_index_template(cfg), indent=2) + "\n"
    )
    out["artifacts/roles-klaxon-customer-a.yaml"] = build_roles_fragment(cfg)

    # --- Committed artifact set (render_artifacts, salt-free __SALT__) ------ #
    from klaxon_mcp.masking import render_artifacts

    for path, content in render_artifacts(cfg).items():
        out[f"artifacts-committed/{Path(path).name}"] = content

    return out


def write_golden() -> list[Path]:
    """Write every captured output under tests/golden/. Returns written paths."""
    written: list[Path] = []
    for rel, content in capture().items():
        p = GOLDEN_DIR / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        written.append(p)
    return written


if __name__ == "__main__":
    for p in write_golden():
        print(f"wrote {p}")
