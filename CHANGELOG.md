# Changelog

All notable changes to Klaxon are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## ## [0.1.3] — 2026-08-08

### Added

- **CORS support for browser-based MCP clients**, via `WAZUH_MCP_CORS_ORIGINS`
  (comma-separated origins, no trailing slash). Unset — the default — emits no
  CORS headers at all, so a deployment that does not need this gains no new
  surface.

  The middleware is installed *outside* the bearer check, because a CORS
  preflight is an unauthenticated `OPTIONS` that browsers never attach
  `Authorization` to. Reaching the bearer check, it would take a 401 carrying no
  `Access-Control-Allow-Origin`, and the browser would report an opaque CORS
  failure that never mentions the token. Requests other than the preflight
  authenticate exactly as before.

  Granted origins are also added to the DNS rebinding allowlist. Without that,
  an origin cleared by the browser preflight was then rejected `403` by the
  SDK's own `Origin` check — two allowlists disagreeing, with only the one the
  operator had *not* set named in the error.

  `mcp-session-id` is named in both `Access-Control-Allow-Headers` and
  `Access-Control-Expose-Headers`. It is not CORS-safelisted in either
  direction, so omitting it loses the session the moment `initialize` returns —
  a failure that reads as the server forgetting the session rather than as a
  CORS problem. `GET`, `POST` and `DELETE` are all granted: streamable HTTP uses
  `POST` for JSON-RPC, `GET` for the server-to-client stream and `DELETE` for
  teardown, so a `POST`-only grant works until the client disconnects.

  `WAZUH_MCP_CORS_ORIGINS=*` is refused at startup. Every tool runs with the
  configured Wazuh credentials, so a wildcard would let any page a browser loads
  read the SIEM from that browser's network position.

- Open WebUI setup guide in the README, covering v0.6.31+ native MCP
  registration and connecting DeepSeek V4 Flash as the chat model.

### Added

- **PII anonymization for external LLM clients (GDPR).** A new layer masks
  personal data in every tool output before it is returned to the MCP client,
  so no unmasked PII reaches a cloud model (DeepSeek, Mistral, ...). Off by
  default; enabled with `KLAXON_ANONYMIZE_EXTERNAL_LLM=true` and active unless
  `KLAXON_LLM_BASE_URL` points at loopback (a local model keeps receiving
  unchanged data; an unset endpoint is treated as external).

  Two masking passes plus a gate: a structured pass replaces values under
  configured fields (`source.ip`, `user.name`, `wazuh.agent.name`, ...) with
  **deterministic placeholders** (`[IP_abc123]`, `[USER_def789]`, ...; MD5 or
  SHA-256 via `KLAXON_ANONYMIZATION_HASH_ALGORITHM`), a text pass masks
  e-mails, IP addresses and usernames in their log context anywhere in the
  rendered output, and the gate blocks a response that still carries residual
  IPs/e-mails (`KLAXON_ANONYMIZATION_WHITELIST_ENABLED`, on by default) instead
  of sending it.

  Every exchange is logged with a UTC timestamp to `llm_prompts.log` (MASKED
  output only; `KLAXON_ANONYMIZATION_LOG_RAW=true` persists raw output and
  warns that the log is then a personal-data store). New one-shot CLI commands
  — `--anonymization-status`, `--anonymization-report [OUTFILE]`,
  `--anonymization-export [OUTFILE]` (RAW lines dropped) — need no Wazuh
  environment and serve the compliance report and access requests.

  The `anonymization:` block can also be configured in an optional YAML file
  (`KLAXON_CONFIG`, default `./config.yaml`; precedence env > YAML > default),
  which adds `pyyaml` as a runtime dependency and `types-PyYAML` to the dev
  extras. Custom rules are added by extending `mask_fields`.

- **DSGVO plausibility checker.** A new `gdpr_check` tool (plus
  `klaxon-mcp --gdpr-check`, `--check-gdpr-on-startup` and the standalone
  `klaxon_check_gdpr` script) finds sensitive fields in an index and merges
  them into the anonymization list. Classification is three-layered: custom
  rules from `gdpr_checker.custom_patterns` in config.yaml (field glob, type,
  priority, optional content regex) beat field-name patterns (`source.ip`,
  `user.name`, `host.hostname`, `user.email`, ...), which beat sampled values
  (a custom field holding `192.168.1.100` is an IP by content; a free-text
  field embedding IPs/e-mails/usernames is flagged as FREETEXT).

  Priorities follow the spec (IPs/usernames/e-mails high, hostnames/agent-ids
  medium); fields already in `mask_fields` are reported as covered, not
  re-suggested. `apply=true` / `--gdpr-auto-add` merges the suggestions into
  `anonymization.mask_fields` of config.yaml, appends to `gdpr_check.log` and
  writes `gdpr_compliance_report.json` (the artifact to forward to a SIEM for
  central compliance monitoring). Without it the check dry-runs, or confirms
  per field on a TTY. `KLAXON_GDPR_CHECK_ON_SEARCH=true` makes `search` append
  a `[GDPR]` notice naming sensitive fields present in the hits.

### Fixed

- **DNS rebinding protection rejected every request when only
  `WAZUH_MCP_ALLOWED_ORIGINS` was set.** Protection was enabled whenever either
  allowlist was non-empty, but the SDK validates `Host` before `Origin`, so an
  empty `WAZUH_MCP_ALLOWED_HOSTS` failed every request with `421` before the
  origin check was ever reached. Enabling it is now keyed on the host allowlist
  alone, and a configured origin list with no host allowlist is logged as
  unenforced rather than silently bricking the listener.

### Changed

- `preflight()` logs the granted CORS origins at startup, and warns when origins
  are granted with no `WAZUH_MCP_AUTH_TOKEN` set — a page from a granted origin
  can then read the SIEM with no credential of its own, which is true even on a
  loopback bind, since the browser is itself on the loopback interface.

### Documentation

- Corrected the claim that Open WebUI needs CORS. Its native MCP integration
  connects from its **backend**, not from the page, so no
  `Access-Control-Allow-Origin` is involved. The CORS guidance in the Open WebUI
  documentation applies to OpenAPI "Direct Tool Servers", a separate
  browser-side feature. `WAZUH_MCP_CORS_ORIGINS` is for genuinely browser-based
  MCP clients only.
- `docs/TOOLS.md` documents `WAZUH_MCP_CORS_ORIGINS` and spells out how it
  differs from `WAZUH_MCP_ALLOWED_ORIGINS`: the latter is a filter over which
  `Origin` values are not rejected, the former is a grant of browser access.

## [0.1.0] — 2026-08-03

Initial public release: eight read-only tools over stdio or HTTP, bearer
authentication, and DNS rebinding protection.

## 0.0.2 — 2026-07-31

Pre-release, published before this repository's history begins. The first commit
here postdates it, so there is no tag and no diff to link — the artefact on PyPI
is the only record.

[Unreleased]: https://github.com/sec73/klaxon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sec73/klaxon/releases/tag/v0.1.0
