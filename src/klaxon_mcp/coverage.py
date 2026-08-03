# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Field coverage: what share of the documents actually carries a value.

`schema` answers this over the whole datastream, and for judging normalisation
quality that is the wrong denominator. A datastream spans decoder generations.
Measured on a live instance for `event.action` in
wazuh-events-v5-network-activity*:

    whole datastream (10,238,381 docs)     8.1 %
    last 24 hours       (348,247 docs)    71.0 %
    last 12 hours                        100.0 %

A decoder fix had landed a few hours earlier. All three numbers are correct and
they describe different things — 8.1 % is the history of the index, 100 % is the
state of the pipeline. A tool that reports only one of them tells a story that
is true in the arithmetic and false in the conclusion, so this module always
reports both and says so out loud when they diverge.

The other half is the zero row. A field that is mapped and never populated is
the most important finding this measurement produces — it is the `agent.id`
trap, and it is what this project was built for. It is never filtered out.

Which is exactly why the zero has to be earned. An exists aggregation returns 0
for a field the mapping declares unindexed, whatever the documents contain.
Verified on the same instance:

    event.original, {"type": "keyword", "index": false, "doc_values": false}
      exists    0 of 10,243,389 documents
      _source   the full raw log line, present in every document sampled

Reported as 0%, that field would be the report's headline normalisation failure,
and the raw log would be sitting in every document. So coverage here is
three-valued — populated, not populated, not measurable — and the third state is
never collapsed into the second.

Pure functions only: counts in, rows out, string out. server.py does the I/O.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .constants import TIME_FIELD
from .fields import FieldInfo, FieldMappingFacts
from .tables import table

# Coverage bands, as percentages of the documents in scope.
COMPLETE_THRESHOLD: Final[float] = 99.0
PARTIAL_THRESHOLD: Final[float] = 50.0

CATEGORY_COMPLETE: Final[str] = "complete"
CATEGORY_PARTIAL: Final[str] = "partial"
CATEGORY_SPARSE: Final[str] = "sparse"
CATEGORY_NEVER: Final[str] = "never"
CATEGORY_UNMEASURABLE: Final[str] = "unmeasurable"

CATEGORY_ORDER: Final[tuple[str, ...]] = (
    CATEGORY_COMPLETE,
    CATEGORY_PARTIAL,
    CATEGORY_SPARSE,
    CATEGORY_NEVER,
    CATEGORY_UNMEASURABLE,
)

CATEGORY_LEGEND: Final[str] = (
    f"STATUS: {CATEGORY_COMPLETE} >= {COMPLETE_THRESHOLD:.0f}%, "
    f"{CATEGORY_PARTIAL} {PARTIAL_THRESHOLD:.0f}-{COMPLETE_THRESHOLD:.0f}%, "
    f"{CATEGORY_SPARSE} below {PARTIAL_THRESHOLD:.0f}%, "
    f"{CATEGORY_NEVER} = 0% (mapped, never populated), "
    f"{CATEGORY_UNMEASURABLE} = the mapping does not let exists answer"
)

# How many documents to pull when checking _source for an unindexed field.
# Enough to tell "always there" from "never there"; not a coverage figure and
# never rendered as one.
SOURCE_SAMPLE_SIZE: Final[int] = 10

REASON_UNINDEXED: Final[str] = 'index:false in the mapping'
REASON_PARTLY_UNINDEXED: Final[str] = 'index:false in some backing indices'
REASON_NO_DOC_VALUES: Final[str] = 'doc_values:false, exists found nothing'

# Percentage points between the window and the whole datastream that count as a
# change in normalisation rather than as noise.
DRIFT_THRESHOLD: Final[float] = 20.0

# How many field names a single drift notice lists before summarising the rest.
DRIFT_NAMES_IN_NOTICE: Final[int] = 10

MISSING = "-"


def window_query(hours: int) -> dict[str, Any]:
    """The time window, as a range query on the one v5 time field."""
    return {"range": {TIME_FIELD: {"gte": f"now-{hours}h"}}}


# --------------------------------------------------------------------------- #
# Rows
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CoverageRow:
    """One field, measured twice: inside the window and across the datastream.

    Both denominators travel with the row. A percentage that has been separated
    from the count it was computed from is a number nobody can check.
    """

    name: str
    type_label: str
    window_docs: int
    window_total: int
    total_docs: int
    grand_total: int
    # How the mapping declares the field. Defaults describe a field exists can
    # answer for, which is what an absent mapping check has to assume.
    unindexed: bool = False
    partially_indexed: bool = False
    doc_values_disabled: bool = False
    # _source evidence for a field exists cannot reach.
    sample_hits: int | None = None
    sample_size: int | None = None

    @property
    def measurable(self) -> bool:
        """Whether an exists aggregation can answer for this field at all.

        Two ways it cannot. `index: false` is decisive on its own — the exists
        query documents it as a reason a document does not match, and the live
        check confirms it. `doc_values: false` is only decisive together with a
        zero result: if the probe found documents the field is plainly
        reachable, and if it found none there is no way to tell an empty field
        from an invisible one, so the honest answer is that it was not measured.
        """
        if self.unindexed:
            return False
        if self.doc_values_disabled and self.window_docs == 0 and self.total_docs == 0:
            return False
        return True

    @property
    def unmeasurable_reason(self) -> str | None:
        if self.unindexed:
            return REASON_UNINDEXED
        if not self.measurable:
            return REASON_NO_DOC_VALUES
        return None

    @property
    def sample_label(self) -> str:
        """_source evidence, phrased as the sample it is."""
        if self.sample_hits is None or not self.sample_size:
            return MISSING
        return f"{self.sample_hits} of {self.sample_size} sampled"

    @staticmethod
    def _pct(docs: int, total: int) -> float | None:
        # No denominator, no percentage. Returning 0.0 for an empty window would
        # report "this field is never filled" about documents that do not exist.
        if total <= 0:
            return None
        return (docs / total) * 100

    @staticmethod
    def _label(docs: int, total: int) -> str:
        """Format a coverage percentage without ever rounding away the finding.

        Two roundings would each erase the distinction this tool is for.
        10,238,000 of 10,238,381 is 99.996 %, which `%.1f` prints as `100.0%` —
        a claim of completeness about 381 documents that lack the field. And 12
        documents out of ten million prints as `0.0%`, which is the notation
        this same table uses for "mapped, never populated".

        So 100.0% is reserved for docs == total, and a non-zero count never
        prints as zero.
        """
        if total <= 0:
            return MISSING
        if docs == total:
            return "100.0%"
        pct = (docs / total) * 100
        if pct >= 99.95:
            return "99.9%"
        if docs > 0 and pct < 0.05:
            return "<0.1%"
        return f"{pct:.1f}%"

    @property
    def window_pct(self) -> float | None:
        if not self.measurable:
            return None
        return self._pct(self.window_docs, self.window_total)

    @property
    def total_pct(self) -> float | None:
        if not self.measurable:
            return None
        return self._pct(self.total_docs, self.grand_total)

    @property
    def window_label(self) -> str:
        if not self.measurable:
            return MISSING
        return self._label(self.window_docs, self.window_total)

    @property
    def total_label(self) -> str:
        if not self.measurable:
            return MISSING
        return self._label(self.total_docs, self.grand_total)

    @property
    def effective_pct(self) -> float | None:
        """The window when it holds documents, the datastream otherwise.

        The window is the primary lens: it describes the pipeline as it runs
        now. When it is empty there is nothing to describe, and falling back to
        the datastream is better than reporting nothing at all — as long as the
        table says which one is being shown, which it does.
        """
        return self.window_pct if self.window_total > 0 else self.total_pct

    @property
    def effective_docs(self) -> int:
        return self.window_docs if self.window_total > 0 else self.total_docs

    @property
    def drift(self) -> float | None:
        """Window coverage minus datastream coverage, in percentage points."""
        window, total = self.window_pct, self.total_pct
        if window is None or total is None:
            return None
        return window - total

    @property
    def drifted(self) -> bool:
        drift = self.drift
        return drift is not None and abs(drift) > DRIFT_THRESHOLD

    @property
    def category(self) -> str:
        if not self.measurable:
            return CATEGORY_UNMEASURABLE
        pct = self.effective_pct
        if pct is None:
            return CATEGORY_NEVER if self.effective_docs == 0 else CATEGORY_SPARSE
        if pct >= COMPLETE_THRESHOLD:
            return CATEGORY_COMPLETE
        if pct >= PARTIAL_THRESHOLD:
            return CATEGORY_PARTIAL
        if pct > 0:
            return CATEGORY_SPARSE
        return CATEGORY_NEVER


def build_rows(
    fields: Sequence[FieldInfo],
    window_counts: Mapping[str, int],
    total_counts: Mapping[str, int],
    window_total: int,
    grand_total: int,
    mappings: Mapping[str, FieldMappingFacts] | None = None,
    samples: Mapping[str, int] | None = None,
    sample_size: int | None = None,
) -> list[CoverageRow]:
    """One row per mapped field, in the order the fields were given.

    A field missing from the probe results counts as 0, not as absent: the
    exists aggregation answers for every field it was asked about, so a missing
    key means the field holds no value anywhere in scope. That is a finding, and
    dropping the row would hide it.

    Unless the mapping says exists could not have answered — then the row
    carries that fact instead, and the 0 never becomes a percentage.
    """
    mappings = mappings or {}
    samples = samples or {}

    rows = []
    for info in fields:
        facts = mappings.get(info.name)
        rows.append(
            CoverageRow(
                name=info.name,
                type_label=info.type_label,
                window_docs=int(window_counts.get(info.name, 0)),
                window_total=window_total,
                total_docs=int(total_counts.get(info.name, 0)),
                grand_total=grand_total,
                unindexed=bool(facts and facts.unindexed),
                partially_indexed=bool(facts and facts.partially_indexed),
                doc_values_disabled=bool(facts and facts.doc_values_disabled),
                sample_hits=samples.get(info.name),
                sample_size=sample_size if info.name in samples else None,
            )
        )
    return rows


def sort_rows(rows: Sequence[CoverageRow]) -> list[CoverageRow]:
    """Descending by coverage, then by documents, then by name.

    Unmeasured fields sort to the bottom as a group. They hold no coverage
    figure, so ordering them among fields that do would put them on a scale they
    were never placed on.
    """
    return sorted(
        rows,
        key=lambda r: (
            r.measurable is False,
            -(r.effective_pct or 0.0),
            -r.effective_docs,
            r.name,
        ),
    )


def apply_min_docs(
    rows: Sequence[CoverageRow], min_docs: int
) -> tuple[list[CoverageRow], list[CoverageRow]]:
    """Split into (kept, hidden) on the document count in the primary lens.

    Hidden rows are returned rather than discarded so the caller can say how
    many disappeared. min_docs above 0 removes exactly the fields this tool
    exists to surface, so it must never be a silent filter.

    Unmeasured fields are never hidden: their count is not a low count, it is
    the absence of one, and there is nothing for a threshold to compare against.
    """
    if min_docs <= 0:
        return list(rows), []
    kept = [r for r in rows if not r.measurable or r.effective_docs >= min_docs]
    hidden = [r for r in rows if r.measurable and r.effective_docs < min_docs]
    return kept, hidden


def category_counts(rows: Sequence[CoverageRow]) -> dict[str, int]:
    counts = {name: 0 for name in CATEGORY_ORDER}
    for row in rows:
        counts[row.category] += 1
    return counts


# --------------------------------------------------------------------------- #
# Diagnostics
# --------------------------------------------------------------------------- #


def drift_notice(rows: Sequence[CoverageRow], hours: int) -> str | None:
    """Report fields whose window coverage parts company with their history.

    This is the notice the tool exists for. A field at 100 % in the window and
    8 % across the datastream is not a contradiction — it is a decoder change
    with a date, and the two numbers are the evidence.
    """
    drifted = [r for r in rows if r.drifted]
    if not drifted:
        return None

    drifted.sort(key=lambda r: -abs(r.drift or 0.0))
    shown = drifted[:DRIFT_NAMES_IN_NOTICE]
    detail = ", ".join(
        f"{r.name} ({r.window_label} in window vs {r.total_label} overall, "
        f"{_fmt_drift(r.drift)})"
        for r in shown
    )
    more = (
        f" and {len(drifted) - len(shown)} further field(s)"
        if len(drifted) > len(shown)
        else ""
    )
    return (
        f"[COVERAGE DRIFT] {len(drifted)} field(s) differ by more than "
        f"{DRIFT_THRESHOLD:.0f} percentage points between the last {hours}h and the "
        f"whole datastream: {detail}{more}. Both numbers are correct and they "
        f"describe different things — the datastream figure includes documents "
        f"written by earlier decoder generations. A gap this size points at a "
        f"change in normalisation inside the datastream, so quote the window "
        f"figure for the current pipeline and the datastream figure for the "
        f"stored history, never one as if it were the other."
    )


def unmeasurable_notice(rows: Sequence[CoverageRow]) -> str | None:
    """State which fields were not measured, and why, before anyone reads a 0.

    The notice this feature exists for. An unindexed field answers every exists
    aggregation with 0, so reporting it as 0% coverage would hand a report its
    most alarming line — about a field whose value is sitting in _source of
    every document.
    """
    unmeasured = [r for r in rows if not r.measurable]
    if not unmeasured:
        return None

    detail = ", ".join(f"{r.name} ({r.unmeasurable_reason})" for r in unmeasured)
    evidence = [r for r in unmeasured if r.sample_hits]
    found = (
        " A _source sample nonetheless found a value for "
        + ", ".join(f"{r.name} in {r.sample_label}" for r in evidence)
        + " — these fields carry data that no exists aggregation can see."
        if evidence
        else ""
    )
    return (
        f"[NOT MEASURABLE] {len(unmeasured)} field(s) cannot be measured with an "
        f"exists aggregation, because of how the mapping declares them: {detail}. "
        f"They are listed with status {CATEGORY_UNMEASURABLE!r} and dashes rather "
        f"than 0%, which would be a statement about the data instead of about the "
        f"mapping.{found} To check one of these, read it out of _source with "
        f"`search` — coverage cannot be computed for it at all."
    )


def partially_indexed_notice(rows: Sequence[CoverageRow]) -> str | None:
    """Coverage over a field that only some backing indices index is a floor."""
    partial = [r for r in rows if r.partially_indexed and r.measurable]
    if not partial:
        return None
    names = ", ".join(r.name for r in partial)
    return (
        f"[PARTIALLY INDEXED] {len(partial)} field(s) are declared index:false in "
        f"some of the backing indices but not all: {names}. Documents in those "
        f"indices cannot match an exists query whatever they contain, so the "
        f"coverage below is a lower bound for these rows, not a measurement. A "
        f"mapping that differs between backing indices is itself the finding — it "
        f"means the declaration changed at a rollover."
    )


def never_populated_notice(rows: Sequence[CoverageRow]) -> str | None:
    """Name the mapped-but-empty fields. The headline finding, not a footnote."""
    never = [r for r in rows if r.category == CATEGORY_NEVER]
    if not never:
        return None
    return (
        f"[MAPPED BUT NEVER POPULATED] {len(never)} of {len(rows)} field(s) hold "
        f"no value in a single document in scope, listed with status "
        f"{CATEGORY_NEVER!r}. They are mapped and indexed, so the zero is a "
        f"property of the data: querying or aggregating on them returns empty "
        f"results with HTTP 200 and no error. This is the `agent.id` trap, and "
        f"these rows are the most important part of this measurement. They are "
        f"never filtered out — and they are only ever fields the mapping allows "
        f"exists to answer for, which is what makes the zero mean anything."
    )


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _fmt_drift(value: float | None) -> str:
    if value is None:
        return MISSING
    # Without this, a difference of -0.004 points prints as "-0.0pp", which
    # reads as a decline that is not there.
    return f"{0.0 if abs(value) < 0.05 else value:+.1f}pp"


def render_rows(rows: Sequence[CoverageRow], window_measured: bool) -> str:
    """The coverage table. `window_measured` is false for an empty window."""
    body = [
        [
            row.name,
            row.type_label,
            # A count is printed only where one was taken: not for a field
            # exists cannot answer, and not for a window holding no documents.
            str(row.window_docs) if row.measurable and window_measured else MISSING,
            row.window_label,
            str(row.total_docs) if row.measurable else MISSING,
            row.total_label,
            _fmt_drift(row.drift),
            row.category,
        ]
        for row in rows
    ]
    return table(
        [
            "FIELD",
            "TYPE",
            "DOCS_WINDOW",
            "COVERAGE",
            "DOCS_TOTAL",
            "DATASTREAM",
            "DRIFT",
            "STATUS",
        ],
        body,
        right=(2, 3, 4, 5, 6),
    )


def render_unmeasurable(rows: Sequence[CoverageRow]) -> str | None:
    """The detail block: why each field could not be measured, and what _source
    says about it anyway.

    The sample column is the point of this block. "Not measurable" on its own
    leaves a reader guessing whether the field is populated; "not measurable,
    and present in 10 of 10 documents sampled" answers the actual question.
    """
    unmeasured = [r for r in rows if not r.measurable]
    if not unmeasured:
        return None
    body = [
        [r.name, r.type_label, r.unmeasurable_reason or MISSING, r.sample_label]
        for r in unmeasured
    ]
    return table(["FIELD", "TYPE", "REASON", "_SOURCE"], body)


def render_summary(rows: Sequence[CoverageRow]) -> str:
    counts = category_counts(rows)
    return "  ".join(f"{name}: {counts[name]}" for name in CATEGORY_ORDER)


def render(rows: Sequence[CoverageRow], window_measured: bool) -> str:
    sections = [render_rows(rows, window_measured)]
    detail = render_unmeasurable(rows)
    if detail:
        sections.append(
            "NOT MEASURABLE  (the mapping does not let an exists aggregation "
            "answer for these)\n" + detail
        )
    sections.append(render_summary(rows))
    sections.append(CATEGORY_LEGEND)
    return "\n\n".join(sections)


def header(
    index: str,
    prefix: str | None,
    hours: int,
    window_total: int | None,
    grand_total: int | None,
    mapped: int,
    measured: int,
) -> str:
    """What was measured, over what, before any percentage is read."""
    window = MISSING if window_total is None else str(window_total)
    total = MISSING if grand_total is None else str(grand_total)
    return "\n".join(
        [
            f"index:          {index}",
            f"prefix:         {prefix or '* (all)'}",
            f"window:         last {hours}h ({TIME_FIELD} >= now-{hours}h)",
            f"documents:      {window} in window / {total} in datastream",
            f"fields:         {mapped} mapped, {measured} measured",
        ]
    )
