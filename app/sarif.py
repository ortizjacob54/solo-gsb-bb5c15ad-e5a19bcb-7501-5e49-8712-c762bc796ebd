"""Convert a stored audit record into a SARIF 2.1.0 report.

The output follows the SARIF v2.1.0 OASIS standard so the report can be
imported by code-scanning platforms (GitHub code scanning, Azure DevOps
SARIF tasks, ...).

One ``reportingDescriptor`` (rule) is generated for every finding class that
actually occurs, and one ``result`` for:

1. every *control-character error* (an orphan opener/closer or a control
   rejected because the nesting-depth limit was exceeded), and
2. every *dangerous span* (override scope / unclosed scope).

Result ``level`` is mapped from the finding's own ``risk``.  Regions use
**UTF-16 code-unit** column offsets (the SARIF convention), recomputed
line by line from the stored original text -- the line/column stored on the
control are code-point based and cannot be reused directly.

Each result carries stable ``partialFingerprints`` derived from the rule id,
the offending codepoint and the affected range.  All list/key ordering is
deterministic.
"""

from __future__ import annotations

import bisect
import hashlib
import re
from typing import Any

from .bidi import escape_preview

SARIF_VERSION = "2.1.0"
SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "bidi-audit"

# Per-record default artifact URI when the audit has no recorded filename.
def _default_uri(audit_id: Any) -> str:
    return f"audit-{audit_id}"


# risk level (as stored in audit results) -> SARIF result level.
# SARIF only defines "none", "note", "warning", "error".
_RISK_TO_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "warning",
    "critical": "error",
}

# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------

# id -> (stable name, default level, short description, full description, tags)
_RULE_CATALOGUE: dict[str, tuple[str, str, str, str, list[str]]] = {
    "bidi/unclosed-opener": (
        "UnclosedBidiOpener",
        "warning",
        "Unclosed bidi control opener",
        (
            "A bidirectional control opener (LRE/RLE/LRO/RLO/LRI/RLI/FSI) "
            "has no matching closer (PDF/PDI). Its effect extends beyond the "
            "intended scope; an unclosed LRO/RLO override reorders everything "
            "to the end of the text (Trojan Source, CVE-2021-42574)."
        ),
        ["bidi", "trojan-source", "unicode", "unclosed"],
    ),
    "bidi/orphan-closer": (
        "OrphanBidiCloser",
        "warning",
        "Bidi control closer without a matching opener",
        (
            "A PDF (U+202C) or PDI (U+2069) appears without a matching "
            "embedding/isolate opener. Stray closers are usually evidence of "
            "tampering or of a truncated bidi sequence."
        ),
        ["bidi", "trojan-source", "unicode", "orphan"],
    ),
    "bidi/nesting-depth": (
        "BidiNestingDepthExceeded",
        "error",
        "Bidi explicit nesting depth limit exceeded",
        (
            "The UAX #9 explicit embedding/isolate nesting depth limit (125, "
            "BD13) was exceeded; the control character is ignored by compliant "
            "renderers and the intended pairing structure cannot be recovered."
        ),
        ["bidi", "trojan-source", "unicode", "nesting-depth"],
    ),
    "bidi/dangerous-span": (
        "DangerousBidiSpan",
        "warning",
        "Dangerous bidirectional override/scope span",
        (
            "A span of text lies inside a directional override (LRO/RLO) or an "
            "unclosed bidi scope and is visually reordered when rendered, so "
            "the displayed code may not match the logical source."
        ),
        ["bidi", "trojan-source", "unicode", "span"],
    ),
}


# ---------------------------------------------------------------------------
# UTF-16 column helpers
# ---------------------------------------------------------------------------

def _utf16_len(text: str) -> int:
    """Length of *text* in UTF-16 code units (each astral char counts 2)."""
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in text)


def _line_starts(text: str) -> list[int]:
    """Code-point indices where each line starts; index 0 always holds 0."""
    starts = [0]
    starts.extend(i + 1 for i, ch in enumerate(text) if ch == "\n")
    return starts


def _region(text: str, start: int, end: int,
            line_starts: list[int]) -> dict[str, int]:
    """Build a SARIF ``region`` with 1-based lines and UTF-16 columns.

    *start* / *end* are code-point offsets; *end* is exclusive.  Columns are
    measured from the first character of the line in UTF-16 code units, as
    required by SARIF (``column`` 1-based, ``endColumn`` exclusive).
    """
    start = max(0, min(start, len(text)))
    end = max(start, min(end, len(text)))

    start_line = bisect.bisect_right(line_starts, start)
    end_line = bisect.bisect_right(line_starts, end)
    start_line_base = line_starts[start_line - 1]
    end_line_base = line_starts[end_line - 1]
    start_col = _utf16_len(text[start_line_base:start]) + 1
    end_col = _utf16_len(text[end_line_base:end]) + 1

    return {
        "startLine": start_line,
        "startColumn": start_col,
        "endLine": end_line,
        "endColumn": end_col,
    }


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------

def _fingerprint(rule_id: str, codepoint: str, start: int, end: int,
                 uri: str) -> dict[str, str]:
    """Stable partial fingerprints derived from codepoint, range and rule.

    The primary value hashes the rule id, offending codepoint, the affected
    range and the artifact URI; human-readable ingredients are included as
    separate keys so the fingerprint stays auditable.
    """
    basis = f"{rule_id}|{codepoint}|{start}:{end}|{uri}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return {
        "bidiAuditV1/sha256": digest,
        "bidiAuditV1/codepoint": codepoint,
        "bidiAuditV1/range": f"{start}:{end}",
        "bidiAuditV1/ruleId": rule_id,
    }


# ---------------------------------------------------------------------------
# Finding classification
# ---------------------------------------------------------------------------

def _depth_overflow_indices(errors: list[str]) -> set[int]:
    """Logical indices of controls rejected for exceeding the depth limit.

    Stored control records do not carry an overflow flag, but the parser
    records a dedicated error sentence containing the logical index.
    """
    pattern = re.compile(
        r"at logical index (\d+) .*ignored: explicit nesting depth limit"
    )
    return {int(match.group(1)) for msg in errors
            for match in [pattern.search(msg)] if match}


def _rule_for_control(control: dict[str, Any],
                      overflow: set[int]) -> str:
    """Rule id for a control-character error."""
    index = int(control.get("logical_index", -1))
    if index in overflow:
        return "bidi/nesting-depth"
    if control.get("is_orphan"):
        kind = control.get("kind")
        if kind in ("pop_directional", "isolate_terminator"):
            return "bidi/orphan-closer"
        return "bidi/unclosed-opener"
    # Safety net: any control carrying an error but no orphan flag.
    return "bidi/orphan-closer"


def _control_message(control: dict[str, Any], rule_id: str,
                     region: dict[str, int]) -> str:
    abbr = control["abbreviation"]
    codepoint = control["codepoint"]
    at = (f" at line {region['startLine']}, column {region['startColumn']} "
          f"(logical index {control['logical_index']})")
    if rule_id == "bidi/nesting-depth":
        return (
            f"{abbr} ({codepoint}){at} ignored: explicit bidi nesting depth "
            f"limit (125) exceeded"
        )
    if rule_id == "bidi/orphan-closer":
        expected = ("embedding opener (LRE/RLE/LRO/RLO)"
                    if abbr == "PDF"
                    else "isolate opener (LRI/RLI/FSI)")
        return (
            f"{abbr} ({codepoint}){at} has no matching {expected}"
        )
    # unclosed opener
    closer = "PDF" if control.get("kind") in ("embedding", "override") else "PDI"
    return (
        f"Unclosed {abbr} ({codepoint}){at}: never terminated by {closer}"
    )


def _span_message(span: dict[str, Any]) -> str:
    return (
        f"{span['opener']} dangerous span (logical index {span['start']}.."
        f"{span['end']}): {span['reason']}"
    )


# ---------------------------------------------------------------------------
# Result builders
# ---------------------------------------------------------------------------

def _physical_location(uri: str, region: dict[str, int]) -> dict[str, Any]:
    return {
        "artifactLocation": {"uri": uri},
        "region": region,
    }


def _build_control_result(control: dict[str, Any], text: str,
                          uri: str, overflow: set[int],
                          line_starts: list[int]) -> dict[str, Any]:
    rule_id = _rule_for_control(control, overflow)
    start = int(control["logical_index"])
    end = start + 1
    level = _RISK_TO_LEVEL[control.get("risk", "info")]
    region = _region(text, start, end, line_starts)
    snippet = escape_preview(text[start:end])
    properties = {
        "risk": control.get("risk", "info"),
        "codepoint": control["codepoint"],
        "abbreviation": control["abbreviation"],
        "kind": control.get("kind"),
        "logicalIndex": start,
        "depthAfter": control.get("depth_after"),
        "scopeEnd": control.get("scope_end"),
        "pairedWith": control.get("paired_with"),
        "isOrphan": bool(control.get("is_orphan")),
    }
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": _control_message(control, rule_id, region)},
        "locations": [{
            "physicalLocation": _physical_location(
                uri, {**region, "snippet": {"text": snippet}}),
        }],
        "partialFingerprints": _fingerprint(
            rule_id, control["codepoint"], start, end, uri),
        "properties": properties,
    }


def _build_span_result(span: dict[str, Any], opener_by_index: dict[int, dict],
                       text: str, uri: str,
                       line_starts: list[int]) -> dict[str, Any]:
    rule_id = "bidi/dangerous-span"
    start = int(span["start"])
    end = int(span["end"])
    level = _RISK_TO_LEVEL[span.get("risk", "info")]
    opener = opener_by_index.get(start, {})
    codepoint = opener.get("codepoint", f"OPENER:{span.get('opener', '')}")
    properties = {
        "risk": span.get("risk", "info"),
        "opener": span.get("opener"),
        "openerCodepoint": codepoint,
        "logicalStart": start,
        "logicalEnd": end,
        "reason": span.get("reason", ""),
        "escapedPreview": span.get("escaped_preview", ""),
    }
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": _span_message(span)},
        "locations": [{
            "physicalLocation": _physical_location(
                uri, {**_region(text, start, end, line_starts),
                      "snippet": {"text": span.get("escaped_preview", "")}}),
        }],
        "partialFingerprints": _fingerprint(
            rule_id, codepoint, start, end, uri),
        "properties": properties,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_sarif(record: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log (one run) from a stored audit *record*.

    The record is the shape returned by :func:`app.database.get_audit`.
    """
    audit_id = record["id"]
    result = record.get("result", {})
    text = record.get("raw_text", "")
    filename = record.get("filename")
    uri = filename if filename else _default_uri(audit_id)

    controls = result.get("controls", [])
    spans = result.get("dangerous_spans", [])
    opener_by_index = {int(c["logical_index"]): c for c in controls}
    line_starts = _line_starts(text)

    # Error controls: orphan openers/closers and depth-limit rejections.
    overflow = _depth_overflow_indices(result.get("errors", []))
    error_controls = [c for c in controls if c.get("is_orphan")]
    error_controls = sorted(error_controls,
                            key=lambda c: int(c["logical_index"]))

    results: list[dict[str, Any]] = [
        _build_control_result(c, text, uri, overflow, line_starts)
        for c in error_controls
    ]
    results.extend(
        _build_span_result(s, opener_by_index, text, uri, line_starts)
        # spans are produced in document order; sort defensively for stability
        for s in sorted(spans, key=lambda s: (int(s["start"]), int(s["end"])))
    )
    # Deterministic order: document position, then rule id.
    results.sort(key=lambda r: (
        r["locations"][0]["physicalLocation"]["region"]["startLine"],
        r["locations"][0]["physicalLocation"]["region"]["startColumn"],
        r["ruleId"],
    ))

    used_rule_ids = sorted({r["ruleId"] for r in results})
    rules = [_rule_descriptor(rid) for rid in used_rule_ids]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": "1.0.0",
                "semanticVersion": "1.0.0",
                "rules": rules,
            },
        },
        "results": results,
        "artifacts": [{"location": {"uri": uri}}],
        "properties": {
            "auditId": audit_id,
            "riskLevel": result.get("risk_level", "info"),
            "errorCount": result.get("error_count", 0),
            "filenameMissing": not bool(filename),
        },
    }

    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def _rule_descriptor(rule_id: str) -> dict[str, Any]:
    name, level, short, full, tags = _RULE_CATALOGUE[rule_id]
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "defaultConfiguration": {"level": level},
        "help": {"text": full},
        "properties": {"tags": sorted(tags)},
    }
