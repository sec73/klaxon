# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Shared value-classification patterns (IPv4 / IPv6 / e-mail / FQDN).

Single home for the value-type regexes used by both the response layer
(anonymization) and the GDPR checker (gdpr). They must agree on what an IPv4
address, IPv6 address, e-mail or FQDN is: the anonymizer masks by them and
`verify()` re-scans with them, and `gdpr.classify_field` classifies sampled
values with them — a divergence between the two copies would let a residual
slip through or misclassify a field.

A leaf: imports nothing from the package, imported widely.
"""

from __future__ import annotations

import re


def _ipv4() -> str:
    octet = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
    return rf"\b(?:{octet}\.){{3}}{octet}\b"


_IPV4_RE = re.compile(_ipv4())
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_FQDN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)
