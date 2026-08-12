# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Painless script generation for the Option B ingest pipeline.

Owns the free-text pattern table (`_PATTERNS`, `_FREETEXT_PATTERN_ORDER`,
`_FREETEXT_ALWAYS_ON`, `_active_free_text_patterns`, `_MASK_FAMILY`) and the
Painless emitter (`_painless_script`, `_painless_regex`). The Python-side
pattern table is ALSO compiled by the pipeline twin (`pipeline_mask_doc` in
masked_stream) so the pipeline logic is unit-testable without a cluster; both
must stay in lock-step with the response-layer patterns in anonymization.py.

The emission rules are pinned against the LIVE cluster (see `klaxon masking
test`): Painless requires every function declaration to precede any top-level
statement, and functions can only read their parameters, local variables and
other functions — so all shared data (salt, field table) is threaded into the
functions from the main logic.
"""

from __future__ import annotations

import json

from .tenants import TenantConfig

# Painless regex source strings. These are ALSO compiled by the Python reference
# implementation (`pipeline_mask_doc`) so the pipeline logic is unit-testable
# without a cluster; both must stay in lock-step with the response-layer
# patterns in anonymization.py.
_PATTERNS: dict[str, str] = {
    "EMAIL": r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "IPV6": r"(?i)\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b",
    "IPV4": r"(?i)\b(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\b",
    "USER_NOUN": r"(?i)\b(?:user|username|user[-_ ]?name|account)\b\s*(?:name)?\s*[:=]\s*(?:\"|'|`)?([\w.@%+=-]{2,64})",
    "USER_AUTH": r"(?i)\b(?:login|logon|sign[- ]?in|authenticat(?:e|ed|ion))\b\s+(?:as|for|by)\s+(?:\buser\b\s+)?([\w.@%+=-]{2,64})\b",
    "UID_EQ": r"(?i)\buid\s*=\s*([^\W\d_][\w.@%+=-]{1,63})\b",
    "FOR_USER": r"(?i)\b(?:for|by)\s+user\s+([\w.@%+=-]{2,64})\b",
    "SSH_PUBKEY": r"(?i)\bAccepted\s+publickey\s+for\s+([\w.@%+=-]{2,64})\b",
    "UID_PAREN": r"(?i)\b(?:by|as|for)\s+([\w.@%+=-]{2,64})\s*\(\s*uid\s*=\s*\d+\s*\)",
}

# Order matters for the free-text pass (value types first, then usernames).
_FREETEXT_PATTERN_ORDER = (
    "EMAIL",
    "IPV6",
    "IPV4",
    "USER_NOUN",
    "USER_AUTH",
    "UID_EQ",
    "FOR_USER",
    "SSH_PUBKEY",
    "UID_PAREN",
)

# Always-on free-text patterns (EMAIL/IP + the two basic username-noun/auth
# context patterns) — mirrors the response layer's `mask_text`, where the
# broader username registry and context patterns are gated on
# `mask_free_text_users` while these always run.
_FREETEXT_ALWAYS_ON = ("EMAIL", "IPV6", "IPV4", "USER_NOUN", "USER_AUTH")


def _active_free_text_patterns(cfg: TenantConfig) -> tuple[str, ...]:
    if cfg.mask_free_text_users:
        return _FREETEXT_PATTERN_ORDER
    return _FREETEXT_ALWAYS_ON


# --------------------------------------------------------------------------- #
# Ingest pipeline (Painless)
# --------------------------------------------------------------------------- #


def _painless_script(cfg: TenantConfig) -> str:
    """The Painless source for the masking pipeline, built from fields.yaml.

    The salt is NOT embedded in the source: the script reads `params.salt`, set
    on the script processor (the template carries `__SALT__` so the secret never
    enters git; the deployable pipeline carries the real salt). The script
    contains no hardcoded field names either — the field table is injected as
    the `FIELDS`/`FREE_TEXT` lists below.

    The emission rules are pinned against the LIVE cluster (see `klaxon masking
    test`): Painless requires every function declaration to precede any
    top-level statement, AND functions can only read their parameters, local
    variables and other functions (NOT `params`, NOT top-level `def`s) — so all
    shared data (the salt, the field table) is threaded into the functions from
    the main logic. The hash uses the ingest-context `String.sha256()`
    augmentation (byte-identical to `MessageDigest "SHA-256"`), the free-text
    regexes are regex literals wrapped in `Pattern` functions (the cluster does
    not whitelist `Pattern.compile`), and the known-identity registry does a
    manual word-boundary replacement (the cluster's `String.replaceAll` is not
    usable and `Pattern.compile` is unavailable for a per-value dynamic regex).
    `ctx` IS the ingest document (no nested `_source`).
    """
    field_rows = ",\n    ".join(
        json.dumps(f.to_painless_row()) for f in cfg.fields
    )
    free_text_rows = ", ".join(json.dumps(f) for f in cfg.free_text_fields)

    pattern_fns = "\n".join(
        f'Pattern {name}() {{ return /{_painless_regex(name)}/; }}'
        for name in _FREETEXT_PATTERN_ORDER
    )
    pattern_uses = "\n".join(
        f'        out = maskPattern({name}(), out, "{_MASK_FAMILY[name]}", SALT);'
        for name in _active_free_text_patterns(cfg)
    )
    registry_line = (
        "    // Known identities first, so free text reuses the exact structured token.\n"
        "    out = maskRegistry(out, source, FIELDS, SALT);"
        if cfg.mask_free_text_users
        else "    // mask_free_text_users: false -> registry + broader username patterns skipped."
    )
    return f"""// Generated from {cfg.source_rel} — do not edit by hand.
// klaxon-mask-{cfg.tenant}: deterministic masking for {cfg.masked_stream_pattern}.

// ---- Functions first. Painless requires EVERY function declaration to precede
// any top-level statement, and functions can only read their parameters, local
// variables and other functions (NOT `params`, NOT top-level defs) — so all
// shared data (salt, field table) is threaded in from the main logic. ----

String sha256hex(String input) {{
    // SHA-256 via the ingest String augmentation; first 16 hex chars of the
    // digest (byte-identical to MessageDigest "SHA-256").
    return input.sha256().substring(0, 16);
}}

String token(String family, String value, String SALT) {{
    if (value == null) return value;
    if (value.isEmpty()) return value;  // empty stays empty, mirrors derive_token
    if (TOKEN_RE().matcher(value).matches()) return value;  // idempotent
    return "[" + family + "_" + sha256hex(family + ":" + value + ":" + SALT) + "]";
}}

Pattern TOKEN_RE() {{
    // Already-tokenised values are passed through unchanged (idempotency).
    return /^\\[(?:IP|USER|HOST|AGENT)_[0-9a-f]{{16}}\\]$/;
}}

String maskPattern(Pattern p, String text, String family, String SALT) {{
    if (text == null) return text;
    Matcher m = p.matcher(text);
    int last = 0;
    StringBuilder out = new StringBuilder();
    while (m.find()) {{
        out.append(text.substring(last, m.start()));
        // Value-type patterns (EMAIL/IPV6/IPV4) have no capturing group; ask for
        // the whole match then. Calling group(1) on a group-less pattern THROWS
        // "No group 1" in Java, so guard with groupCount() (mirrors the Python
        // twin's `m.lastindex` check).
        String matched = (m.groupCount() >= 1 && m.group(1) != null) ? m.group(1) : m.group(0);
        out.append(token(family, matched, SALT));
        last = m.end();
    }}
    out.append(text.substring(last));
    return out.toString();
}}

boolean isWordChar(int c) {{
    // Mirrors Java/Painless `\\w` for word-boundary decisions (ASCII codes:
    // a-z, A-Z, 0-9, _). `text.charAt(...)` (a char) widens to int implicitly.
    return (c >= 97 && c <= 122) || (c >= 65 && c <= 90)
        || (c >= 48 && c <= 57) || c == 95;
}}

String replaceWordBoundary(String text, String needle, String replacement) {{
    // Manual word-boundary find+replace: no Pattern.compile / replaceAll needed
    // (neither is whitelisted on restricted clusters). Equivalent to replacing
    // every `(?<!\\w)needle(?!\\w)` occurrence, left to right.
    if (needle.isEmpty()) return text;
    StringBuilder sb = new StringBuilder();
    int i = 0;
    while (true) {{
        int idx = text.indexOf(needle, i);
        if (idx < 0) {{ sb.append(text.substring(i)); break; }}
        int end = idx + needle.length();
        boolean leftOk = idx == 0 || !isWordChar(text.charAt(idx - 1));
        boolean rightOk = end >= text.length() || !isWordChar(text.charAt(end));
        if (leftOk && rightOk) {{
            sb.append(text.substring(i, idx));
            sb.append(replacement);
        }} else {{
            sb.append(text.substring(i, end));
        }}
        i = end;
    }}
    return sb.toString();
}}

String maskRegistry(String text, Map source, List FIELDS, String SALT) {{
    if (text == null) return text;
    String out = text;
    for (def entry : FIELDS) {{
        if (entry[1] != "USER") continue;
        String f = entry[0];
        if (!source.containsKey(f)) continue;
        def v = source.get(f);
        List vals = new ArrayList();
        if (v instanceof List) {{ for (item in v) {{ if (item instanceof String) vals.add(item); }} }}
        else if (v instanceof String) vals.add(v);
        for (raw in vals) {{
            String rawStr = (String) raw;
            if (rawStr.length() < 2) continue;
            String tok = token("USER", rawStr, SALT);
            if (tok == rawStr) continue; // already a token, nothing to do
            out = replaceWordBoundary(out, rawStr, tok);
        }}
    }}
    return out;
}}

String maskFreeText(String text, Map source, List FIELDS, String SALT) {{
    if (text == null) return text;
    String out = text;
{registry_line}
{pattern_uses}
    return out;
}}

// Free-text regexes as Pattern functions (regex literals). The free-text pass
// references them by name; functions may call functions regardless of order, so
// these live with the other functions.
{pattern_fns}

// ---- Top-level definitions (functions first, then statements). The salt is
// read from params.salt so it is never embedded in the source. ----

def SALT = params.salt;  // injected as the script processor's params.salt
def FIELDS = [
    {field_rows}
];
def FREE_TEXT = [
    {free_text_rows}
];

// ---- Main logic. In an ingest script processor `ctx` IS the document (the
// root map) — there is no nested `_source` object. ----

Map masked = new HashMap();
for (key in ctx.keySet()) {{ masked.put(key, ctx.get(key)); }}

for (def entry : FIELDS) {{
    String f = entry[0];
    String family = entry[1];
    boolean array = entry[2];
    if (!masked.containsKey(f)) continue;            // missing field: no-op
    def v = masked.get(f);
    if (array) {{
        if (v instanceof List) {{
            List out = new ArrayList();
            for (item in v) {{
                if (item instanceof String) out.add(token(family, item, SALT));
                else out.add(item);
            }}
            masked.put(f, out);
        }}
    }} else {{
        if (v instanceof String) masked.put(f, token(family, v, SALT));
    }}
}}

for (f in FREE_TEXT) {{
    if (masked.containsKey(f) && masked.get(f) instanceof String) {{
        // Registry reads the RAW original source: free text must re-tokenise the
        // same raw username to the exact structured token.
        masked.put(f, maskFreeText(masked.get(f), ctx, FIELDS, SALT));
    }}
}}

// Commit atomically: only on full success does the document change. A failure is
// caught by the on_failure processor, which flags klaxon.masking_error and keeps
// the (original) document so it can be filtered and fixed.
ctx.clear();
ctx.putAll(masked);
"""


# Painless pattern name -> family (for tokenizing value-type matches).
_MASK_FAMILY = {
    "EMAIL": "EMAIL",
    "IPV6": "IP",
    "IPV4": "IP",
    "USER_NOUN": "USER",
    "USER_AUTH": "USER",
    "UID_EQ": "USER",
    "FOR_USER": "USER",
    "SSH_PUBKEY": "USER",
    "UID_PAREN": "USER",
}


def _painless_regex(name: str) -> str:
    """The regex source emitted into the Painless regex literal for a pattern.

    Same matching semantics as `_PATTERNS[name]`, hardened against the cluster's
    `script.painless.regex.limit-factor` (default 6): greedy quantifiers in the
    value-type patterns read up to ~6x the input (Painless counts every character
    the matcher touches, and a `find()` loop that never matches runs at the
    limit), tripping on dot/digit-heavy log lines. Possessive quantifiers make
    the scan linear (~1x input) while matching the exact same values — the local
    part of the EMAIL pattern only.
    """
    regex = _PATTERNS[name]
    if name == "EMAIL":
        # Local part possessive only (`++` compiles here; `{2,}++` does not).
        # The domain `[A-Za-z0-9.-]+` MUST stay greedy: `.` is in its class, so
        # a possessive domain would eat the dot the TLD's `\.` needs and stop
        # matching real e-mails like noreply@example.com.
        regex = regex.replace(
            "[A-Za-z0-9._%+-]+@",
            "[A-Za-z0-9._%+-]++@",
            1,
        )
    return regex
