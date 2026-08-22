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
from typing import Any

from .tenants import TenantConfig, effective_free_text_fields

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

# Value-type passes (EMAIL/IP) run BEFORE the known-identity registry and the
# username context patterns, exactly like the response layer's `mask_text`: an
# e-mail whose local part is a structured username must mask as a WHOLE e-mail
# (`[EMAIL_...]`), never split into `[USER_...]@example.com` by the registry.
_FREETEXT_VALUE_TYPES = _FREETEXT_PATTERN_ORDER[:3]

# Username context patterns, applied AFTER the registry.
_FREETEXT_USERNAME_PATTERNS = _FREETEXT_PATTERN_ORDER[3:]

# Username context patterns that ALWAYS run (mask_free_text_users: false still
# masks "user X" / "login as X", mirroring the response layer).
_FREETEXT_USERNAME_ALWAYS = ("USER_NOUN", "USER_AUTH")


def _active_free_text_patterns(cfg: TenantConfig) -> tuple[str, ...]:
    if cfg.mask_free_text_users:
        return _FREETEXT_PATTERN_ORDER
    return _FREETEXT_ALWAYS_ON


def _active_username_patterns(cfg: TenantConfig) -> tuple[str, ...]:
    if cfg.mask_free_text_users:
        return _FREETEXT_USERNAME_PATTERNS
    return _FREETEXT_USERNAME_ALWAYS


# --------------------------------------------------------------------------- #
# HMAC-SHA256 in pure Painless (the stream token scheme)
#
# The Option-B token is HMAC-SHA256(key = salt, message = "family:value"),
# first 16 hex chars. The restricted ingest Painless allowlist (verified against
# OpenSearch 3.6.0) has NO javax.crypto.Mac / MessageDigest, and the
# `String.sha256()` augmentation can only hash UTF-8 text (chars >= 0x80 become
# two bytes — it cannot hash the raw 32-byte inner digest of HMAC), so a byte-
# exact HMAC cannot be built on those. Instead SHA-256 is reimplemented here
# over an int[] byte sequence (all primitives are whitelisted), giving the full
# keyed HMAC construction with zero cluster-config dependency. Byte-identical
# to Python's `hmac.new(salt, "family:value", sha256)` — proven by the
# generator self-test (painless_token_reference) and the live `_simulate`
# (Stage B/C of `klaxon masking test`).
# --------------------------------------------------------------------------- #

# SHA-256 initial hash values and round constants as SIGNED decimal ints
# (Painless rejects unsigned hex constants like 0xffffffff / values >= 2^31).
_SHA256_H_SIGNED = (
    1779033703, -1150833019, 1013904242, -1521486534,
    1359893119, -1694144372, 528734635, 1541459225,
)
_SHA256_K_SIGNED = (
    1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993,
    -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
    1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
    264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
    -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
    113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
    1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885,
    -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
    430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
    1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872,
    -1866530822, -1538233109, -1090935817, -965641998,
)

# The Painless source block emitted before `token()`: functions first, every
# function only reading params/locals/other functions (Painless rules). All
# constants are signed decimals. `sha256` returns the 8 32-bit hash words;
# `wordsToBytes`/`wordsToHex` convert for the HMAC composition.
_HMAC_FUNCTIONS = (
    r"""int[] sha256(int[] data) {
    // SHA-256 over a byte sequence (each element 0..255); returns the 8
    // 32-bit hash words. Signed-int arithmetic wraps mod 2^32 exactly like the
    // Java/Python reference. No MessageDigest / javax.crypto needed.
    int origLen = data.length;
    int padLen = ((origLen + 8) / 64 + 1) * 64;
    int[] msg = new int[padLen];
    for (int i = 0; i < origLen; i++) { msg[i] = data[i]; }
    msg[origLen] = 128;
    long bits = (long) origLen * 8;
    for (int i = 0; i < 8; i++) {
        msg[padLen - 1 - i] = (int) ((bits >>> (8 * i)) & 255);
    }
"""
    + "".join(f"    int h{i} = {_SHA256_H_SIGNED[i]};\n" for i in range(8))
    + r"""    int[] K = new int[] {
"""
    + ",\n        ".join(str(v) for v in _SHA256_K_SIGNED)
    + r"""
    };
    int[] w = new int[64];
    for (int block = 0; block < padLen; block += 64) {
        for (int t = 0; t < 16; t++) {
            int o = block + t * 4;
            w[t] = (msg[o] << 24) | (msg[o + 1] << 16) | (msg[o + 2] << 8) | msg[o + 3];
        }
        for (int t = 16; t < 64; t++) {
            int s0 = ror(w[t - 15], 7) ^ ror(w[t - 15], 18) ^ (w[t - 15] >>> 3);
            int s1 = ror(w[t - 2], 17) ^ ror(w[t - 2], 19) ^ (w[t - 2] >>> 10);
            w[t] = w[t - 16] + s0 + w[t - 7] + s1;
        }
        int a = h0; int b = h1; int c = h2; int d = h3;
        int e = h4; int f = h5; int g = h6; int h = h7;
        for (int t = 0; t < 64; t++) {
            int S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
            int ch = (e & f) ^ ((~e) & g);
            int temp1 = h + S1 + ch + K[t] + w[t];
            int S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
            int maj = (a & b) ^ (a & c) ^ (b & c);
            int temp2 = S0 + maj;
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h;
    }
    return new int[] { h0, h1, h2, h3, h4, h5, h6, h7 };
}

int ror(int x, int n) {
    return (x >>> n) | (x << (32 - n));
}

int[] utf8(String s) {
    // UTF-8 byte sequence of a String as int[] (0..255 each), matching
    // Python's .encode("utf-8") including surrogate pairs.
    int len = s.length();
    int n = 0;
    for (int i = 0; i < len; i++) {
        int c = s.charAt(i);
        if (c >= 55296 && c <= 56319 && i + 1 < len) {
            int lo = s.charAt(i + 1);
            if (lo >= 56320 && lo <= 57343) { n += 4; i++; }
            else { n += 3; }
        } else if (c >= 2048) { n += 3; }
        else if (c >= 128) { n += 2; }
        else { n += 1; }
    }
    int[] out = new int[n];
    int p = 0;
    for (int i = 0; i < len; i++) {
        int c = s.charAt(i);
        if (c >= 55296 && c <= 56319 && i + 1 < len) {
            int lo = s.charAt(i + 1);
            if (lo >= 56320 && lo <= 57343) {
                int cp = 65536 + ((c - 55296) << 10) + (lo - 56320);
                out[p++] = 240 | (cp >>> 18);
                out[p++] = 128 | ((cp >>> 12) & 63);
                out[p++] = 128 | ((cp >>> 6) & 63);
                out[p++] = 128 | (cp & 63);
                i++;
                continue;
            }
        }
        if (c >= 2048) {
            out[p++] = 224 | (c >>> 12);
            out[p++] = 128 | ((c >>> 6) & 63);
            out[p++] = 128 | (c & 63);
        } else if (c >= 128) {
            out[p++] = 192 | (c >>> 6);
            out[p++] = 128 | (c & 63);
        } else {
            out[p++] = c;
        }
    }
    return out;
}

int[] wordsToBytes(int[] words) {
    // 8 32-bit words -> 32 bytes, big-endian (the raw SHA-256 digest).
    int[] out = new int[32];
    for (int i = 0; i < 8; i++) {
        int w = words[i];
        out[i * 4] = (w >>> 24) & 255;
        out[i * 4 + 1] = (w >>> 16) & 255;
        out[i * 4 + 2] = (w >>> 8) & 255;
        out[i * 4 + 3] = w & 255;
    }
    return out;
}

String wordsToHex(int[] words) {
    String hex = "0123456789abcdef";
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < words.length; i++) {
        int w = words[i];
        for (int j = 7; j >= 0; j--) {
            sb.append(hex.charAt((w >>> (4 * j)) & 15));
        }
    }
    return sb.toString();
}

String hmacSha256Hex(String salt, String message) {
    // HMAC-SHA256(key = salt, msg = message): a keyed MAC, NOT a
    // concatenation hash. ipad = 0x36, opad = 0x5c; keys longer than the
    // 64-byte block are pre-hashed with SHA-256 (standard HMAC).
    int[] key = utf8(salt);
    int[] kd;
    if (key.length > 64) { kd = wordsToBytes(sha256(key)); }
    else { kd = key; }
    int[] kb = new int[64];
    for (int i = 0; i < 64; i++) { kb[i] = (i < kd.length) ? kd[i] : 0; }
    int[] msg = utf8(message);
    int[] innerInput = new int[64 + msg.length];
    for (int i = 0; i < 64; i++) { innerInput[i] = kb[i] ^ 54; }
    for (int i = 0; i < msg.length; i++) { innerInput[64 + i] = msg[i]; }
    int[] innerBytes = wordsToBytes(sha256(innerInput));
    int[] outerInput = new int[64 + 32];
    for (int i = 0; i < 64; i++) { outerInput[i] = kb[i] ^ 92; }
    for (int i = 0; i < 32; i++) { outerInput[64 + i] = innerBytes[i]; }
    return wordsToHex(sha256(outerInput));
}
"""
)


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
    the main logic. Tokens are a KEYED HMAC-SHA256 (key = salt, message =
    `family:value`) implemented in pure Painless (the ingest allowlist has no
    `javax.crypto.Mac`, and `String.sha256()` cannot hash the raw inner digest
    bytes), byte-identical to Python's `hmac` — see `_HMAC_FUNCTIONS`. The
    free-text regexes are regex literals wrapped in `Pattern` functions (the
    cluster does not whitelist `Pattern.compile`), and the known-identity
    registry does a manual word-boundary replacement (the cluster's
    `String.replaceAll` is not usable and `Pattern.compile` is unavailable for
    a per-value dynamic regex). `ctx` IS the ingest document (no nested
    `_source`).
    """
    field_rows = ",\n    ".join(
        json.dumps(f.to_painless_row()) for f in cfg.fields
    )
    # `message` is the built-in default free-text field and is ALWAYS present
    # (never an empty FREE_TEXT list); `free_text_fields` adds extra fields.
    free_text_rows = ", ".join(
        json.dumps(f) for f in effective_free_text_fields(cfg)
    )

    pattern_fns = "\n".join(
        f'Pattern {name}() {{ return /{_painless_regex(name)}/; }}'
        for name in _FREETEXT_PATTERN_ORDER
    )
    value_uses = "\n".join(
        f'        out = maskPattern({name}(), out, "{_MASK_FAMILY[name]}", SALT);'
        for name in _FREETEXT_VALUE_TYPES
    )
    username_uses = "\n".join(
        f'        out = maskPattern({name}(), out, "{_MASK_FAMILY[name]}", SALT);'
        for name in _active_username_patterns(cfg)
    )
    registry_line = (
        "        // Known identities reuse the exact structured token AFTER the\n"
        "        // value-type passes (mirrors the response layer: a username\n"
        "        // inside an e-mail never splits the e-mail).\n"
        "        out = maskRegistry(out, source, FIELDS, SALT);"
        if cfg.mask_free_text_users
        else "        // mask_free_text_users: false -> registry + broader username patterns skipped."
    )
    return f"""// Generated from {cfg.source_rel} — do not edit by hand.
// klaxon-mask-{cfg.tenant}: deterministic masking for {cfg.masked_stream_pattern}.

// ---- Functions first. Painless requires EVERY function declaration to precede
// any top-level statement, and functions can only read their parameters, local
// variables and other functions (NOT `params`, NOT top-level defs) — so all
// shared data (salt, field table) is threaded in from the main logic. ----

{_HMAC_FUNCTIONS}

String token(String family, String value, String SALT) {{
    if (value == null) return value;
    if (value.isEmpty()) return value;  // empty stays empty, mirrors derive_token
    if (TOKEN_RE().matcher(value).matches()) return value;  // idempotent
    // Keyed HMAC-SHA256 (key = SALT) over family:value, first 16 hex chars —
    // byte-identical to derive_token(value, family, salt).
    return "[" + family + "_" + hmacSha256Hex(SALT, family + ":" + value).substring(0, 16) + "]";
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
        // The structured USER field may be a FLAT dotted key or NESTED —
        // pathGet handles both (real Wazuh events are nested).
        def v = pathGet(source, entry[0]);
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
    // Value-type passes first (EMAIL/IP) — mirrors the response layer: an
    // e-mail whose local part is a structured username masks as a WHOLE
    // e-mail, never split by the registry.
{value_uses}
{registry_line}
{username_uses}
    return out;
}}

// Deep-copy: structured masking writes into a COPY so the raw document `ctx`
// (which the free-text registry reads) stays pristine until the atomic commit.
// A shallow copy would share the nested maps and the registry would see tokens
// instead of the raw usernames.
def deepCopy(def v) {{
    if (v instanceof Map) {{
        Map out = new HashMap();
        for (k in ((Map) v).keySet()) {{ out.put(k, deepCopy(((Map) v).get(k))); }}
        return out;
    }}
    if (v instanceof List) {{
        List out = new ArrayList();
        for (item in (List) v) {{ out.add(deepCopy(item)); }}
        return out;
    }}
    return v;
}}

// The value at a dotted path in a nested doc, or null when any segment is
// missing. Tries the LITERAL dotted key first (some docs flatten a field into
// one dotted key), then walks the nested form. Manual dot scan — no
// String.split (regex) to keep off the restricted ingest allowlist.
def pathGet(Map doc, String path) {{
    if (doc.containsKey(path)) return doc.get(path);
    def current = doc;
    int start = 0;
    for (int i = 0; i <= path.length(); i++) {{
        // Single-quoted '.' is a STRING in Painless, so compare the char to
        // its ASCII int (46) — charAt returns a char and char != String.
        if (i == path.length() || path.charAt(i) == 46) {{
            String part = path.substring(start, i);
            if (!(current instanceof Map)) return null;
            Map m = (Map) current;
            if (!m.containsKey(part)) return null;
            current = m.get(part);
            start = i + 1;
        }}
    }}
    return current;
}}

// Set the value at a dotted path, creating intermediate maps when absent.
// Returns false when a non-map blocks the path (caller keeps the old value).
// NOTE: dot is compared to the ASCII int 46 (single-quoted '.' is a String in
// Painless, and charAt returns a char — char != String).
boolean pathPut(Map doc, String path, def value) {{
    if (doc.containsKey(path)) {{ doc.put(path, value); return true; }}
    def current = doc;
    int start = 0;
    for (int i = 0; i <= path.length(); i++) {{
        // Single-quoted '.' is a STRING in Painless, so compare the char to
        // its ASCII int (46) — charAt returns a char and char != String.
        if (i == path.length() || path.charAt(i) == 46) {{
            String part = path.substring(start, i);
            boolean last = (i == path.length());
            if (!(current instanceof Map)) return false;
            Map m = (Map) current;
            if (last) {{ m.put(part, value); return true; }}
            if (!(m.get(part) instanceof Map)) m.put(part, new HashMap());
            current = m.get(part);
            start = i + 1;
        }}
    }}
    return false;
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

Map masked = deepCopy(ctx);

for (def entry : FIELDS) {{
    String f = entry[0];
    String family = entry[1];
    boolean array = entry[2];
    // Structured fields live at a dotted path that may be NESTED in a real
    // Wazuh doc or a FLAT dotted key — pathGet handles both; missing no-ops.
    def v = pathGet(masked, f);
    if (v == null) continue;            // missing field: no-op
    if (array) {{
        if (v instanceof List) {{
            List out = new ArrayList();
            for (item in v) {{
                if (item instanceof String) out.add(token(family, item, SALT));
                else out.add(item);
            }}
            pathPut(masked, f, out);
        }}
    }} else {{
        if (v instanceof String) pathPut(masked, f, token(family, v, SALT));
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


# --------------------------------------------------------------------------- #
# Quarantine on_failure (fail-closed masking-error routing)
#
# Verified against OpenSearch 3.6.0 (see docs/option-b-masked-stream.md):
#   * `_ingest` is NOT a resolvable Painless variable in on_failure scripts
#     (`cannot resolve symbol [_ingest.on_failure_message]`) — the failure
#     message is only exposed through the `{{ _ingest.on_failure_message }}`
#     value-template of a `set` processor.
#   * A `set` with an unresolvable template does NOT throw: it sets the field
#     to "" — so the script's empty-check falls back to 'unknown' on clusters
#     that only log the message (the "handle both" requirement).
#   * `ignore_failure: true` on that `set` is defense-in-depth for the
#     (hypothetical) case a cluster DOES throw on an unresolvable template:
#     the script then runs with no reason field and defaults to 'unknown'.
#   * The rerouting script must run as a separate processor AFTER the `set`
#     (there is no way to read the message inside the same script on 3.6.0).
#     Order within the script matters: original_index is captured BEFORE
#     `_index` is rewritten.
# --------------------------------------------------------------------------- #

# Field the `set` processor captures the failure message into (dotted field,
# so it lands NESTED as klaxon.quarantine.reason — the script reads it there).
QUARANTINE_REASON_FIELD = "klaxon.quarantine.reason"
# The on_failure_message template, only resolvable in a `set` value within an
# on_failure block on OpenSearch 3.x.
_ON_FAILURE_MESSAGE_TEMPLATE = "{{ _ingest.on_failure_message }}"


def _quarantine_on_failure_script(cfg: TenantConfig) -> str:
    """The Painless source of the on_failure rerouting script.

    FAIL-CLOSED: a document whose masking threw is routed OUT of the masked
    stream into the quarantine stream — it never stays in
    `klaxon-masked-<tenant>-v5*`. Same `ctx`-context pattern as the masking
    script (in an ingest script processor `ctx` IS the document; there is no
    nested `_source`).
    """
    return f"""// Fail-closed: a masking-failure document is rerouted OUT of the masked
// stream into the quarantine stream — it never stays in {cfg.masked_stream_pattern}.
// In an ingest script processor `ctx` IS the document (no nested _source).

// 1. Preserve the original destination BEFORE rerouting (order matters).
ctx.klaxon.quarantine.original_index = ctx['_index'];
// 2. The failure reason was captured by the preceding `set` processor from the
//    _ingest.on_failure_message template (the only way OpenSearch exposes it to
//    on_failure; clusters that only log it yield an empty field). Fall back to
//    'unknown' so the field is always present and searchable.
if (!ctx['klaxon']['quarantine'].containsKey('reason')
    || ctx['klaxon']['quarantine']['reason'] == null
    || ctx['klaxon']['quarantine']['reason'].toString().isEmpty()) {{
    ctx['klaxon']['quarantine']['reason'] = 'unknown';
}}
// 3. Flag the document (the consumer-side filter is now defense-in-depth only).
ctx.klaxon.masking_error = true;
// 4. Reroute into the quarantine stream (matches the quarantine index template,
//    so the target is auto-created and ISM-retained; never re-enters masking).
ctx['_index'] = '{cfg.quarantine_routing_index}';
"""


def _quarantine_on_failure_processors(cfg: TenantConfig) -> list[dict[str, Any]]:
    """The full on_failure block: capture the message, then reroute.

    Two processors because OpenSearch 3.6.0 exposes `_ingest.on_failure_message`
    ONLY through a `set` value-template — a Painless script cannot read it. The
    script (which preserves original_index, sets the flag and rewrites `_index`)
    runs afterwards; `ignore_failure` on the `set` means an unresolvable
    template (logs-only clusters) degrades to `reason: 'unknown'` instead of
    failing the whole on_failure chain.
    """
    return [
        {
            "set": {
                "field": QUARANTINE_REASON_FIELD,
                "value": _ON_FAILURE_MESSAGE_TEMPLATE,
                "ignore_failure": True,
            }
        },
        {
            "script": {
                "lang": "painless",
                "source": _quarantine_on_failure_script(cfg),
            }
        },
    ]


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
