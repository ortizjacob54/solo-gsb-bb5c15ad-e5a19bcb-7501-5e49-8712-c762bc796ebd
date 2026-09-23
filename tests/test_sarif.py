"""Tests for GET /api/v1/audits/{id}/sarif (SARIF 2.1.0 export)."""

import json

LRE = "‪"
RLO = "‮"
PDF = "‬"
LRI = "⁦"
PDI = "⁩"


def _post(client, text, filename=None):
    return client.post("/api/v1/audits", json={"text": text, "filename": filename})


def _sarif(client, audit_id):
    return client.get(f"/api/v1/audits/{audit_id}/sarif")


def _run(body):
    return body["runs"][0]


# --------------------------------------------------------------- transport --

def test_sarif_missing_record_is_404(client):
    resp = _sarif(client, 9999)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


def test_sarif_content_type_and_envelope(client):
    audit_id = _post(client, RLO + "evil" + PDF, "x.txt").json()["id"]
    resp = _sarif(client, audit_id)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/sarif+json"
    body = resp.json()
    assert body["version"] == "2.1.0"
    assert body["$schema"].endswith("sarif-2.1.0.json")
    assert len(body["runs"]) == 1
    run = _run(body)
    assert run["tool"]["driver"]["name"] == "bidi-audit"
    assert run["properties"]["auditId"] == audit_id
    assert run["properties"]["filenameMissing"] is False


def test_sarif_route_does_not_shadow_detail_route(client):
    audit_id = _post(client, "clean", "a.txt").json()["id"]
    assert client.get(f"/api/v1/audits/{audit_id}").status_code == 200
    assert _sarif(client, audit_id).status_code == 200


# ----------------------------------------------------------- rule / result --

def test_sarif_clean_text_has_no_results_but_valid_report(client):
    audit_id = _post(client, "clean text", "clean.txt").json()["id"]
    run = _run(_sarif(client, audit_id).json())
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_balanced_rlo_generates_span_result(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF, "patch.diff").json()["id"]
    run = _run(_sarif(client, audit_id).json())
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "bidi/dangerous-span"
    assert result["level"] == "warning"          # risk high -> warning
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [
        "bidi/dangerous-span"]
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {
        "startLine": 1, "startColumn": 2,
        "endLine": 1, "endColumn": 11,
        "snippet": {"text": "⟨RLO⟩evil.exe"},
    }
    assert result["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "patch.diff"
    assert result["properties"]["risk"] == "high"


def test_sarif_unclosed_rlo_is_critical_error(client):
    audit_id = _post(client, RLO + "bad.exe", "evil.js").json()["id"]
    run = _run(_sarif(client, audit_id).json())
    by_rule = {r["ruleId"]: r for r in run["results"]}
    # one control error + one dangerous span
    assert set(by_rule) == {"bidi/unclosed-opener", "bidi/dangerous-span"}
    opener = by_rule["bidi/unclosed-opener"]
    assert opener["level"] == "error"            # critical -> error
    assert opener["locations"][0]["physicalLocation"]["region"][
        "startColumn"] == 1
    span = by_rule["bidi/dangerous-span"]
    assert span["level"] == "error"
    assert span["properties"]["openerCodepoint"] == "U+202E"
    rule_ids = sorted(r["id"] for r in run["tool"]["driver"]["rules"])
    assert rule_ids == ["bidi/dangerous-span", "bidi/unclosed-opener"]


def test_sarif_lone_pdf_and_pdi_are_orphan_closers(client):
    audit_id = _post(client, "a" + PDF + PDI + "b").json()["id"]
    run = _run(_sarif(client, audit_id).json())
    assert len(run["results"]) == 2
    assert all(r["ruleId"] == "bidi/orphan-closer" for r in run["results"])
    assert all(r["level"] == "warning" for r in run["results"])  # medium
    msgs = " ".join(r["message"]["text"] for r in run["results"])
    assert "PDF" in msgs and "PDI" in msgs
    # document-order sorting: PDF at index 1 before PDI at index 2
    assert run["results"][0]["properties"]["abbreviation"] == "PDF"


def test_sarif_nesting_depth_overflow_rule(client):
    audit_id = _post(client, LRE * 126).json()["id"]
    run = _run(_sarif(client, audit_id).json())
    overflow = [r for r in run["results"]
                if r["ruleId"] == "bidi/nesting-depth"]
    assert len(overflow) == 1
    result = overflow[0]
    assert result["level"] == "error"
    assert result["properties"]["logicalIndex"] == 125
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "bidi/nesting-depth" in rule_ids


# ---------------------------------------------------------- UTF-16 columns --

def test_sarif_columns_are_utf16_units_from_original(client):
    # "a😀RLOx": RLO is at code-point index 2, but column 4 in UTF-16 units
    # (the astral emoji occupies two UTF-16 code units).
    text = "a😀" + RLO + "x"
    audit_id = _post(client, text, "emoji.txt").json()["id"]
    run = _run(_sarif(client, audit_id).json())
    opener = [r for r in run["results"]
              if r["ruleId"] == "bidi/unclosed-opener"][0]
    region = opener["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
    assert region["startColumn"] == 4           # a=1, 😀=2..3, RLO=4
    assert region["endColumn"] == 5
    assert region["snippet"]["text"] == "⟨RLO⟩"


def test_sarif_multiline_region(client):
    # line 1: "abRLOx\n" ; line 2: "y"  (RLO never closed)
    text = "ab" + RLO + "x\ny"
    audit_id = _post(client, text).json()["id"]
    run = _run(_sarif(client, audit_id).json())
    span = [r for r in run["results"]
            if r["ruleId"] == "bidi/dangerous-span"][0]
    region = span["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
    assert region["startColumn"] == 3
    assert region["endLine"] == 2
    assert region["endColumn"] == 2
    assert region["snippet"]["text"] == "⟨RLO⟩x\\ny"


def test_sarif_filename_fallback(client):
    audit_id = _post(client, PDF + "x", None).json()["id"]
    run = _run(_sarif(client, audit_id).json())
    assert run["properties"]["filenameMissing"] is True
    uri = run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"]
    assert uri == f"audit-{audit_id}"
    assert run["artifacts"][0]["location"]["uri"] == f"audit-{audit_id}"


# ----------------------------------------------------------- fingerprints --

def test_sarif_partial_fingerprints_are_stable_and_unique(client):
    text = "x" + RLO + "evil" + PDF
    first_id = _post(client, text, "same.diff").json()["id"]
    second_id = _post(client, text, "same.diff").json()["id"]
    run1 = _run(_sarif(client, first_id).json())
    run2 = _run(_sarif(client, second_id).json())
    fp1 = run1["results"][0]["partialFingerprints"]
    fp2 = run2["results"][0]["partialFingerprints"]
    # identical codepoint/range/rule -> identical fingerprints across records
    assert fp1 == fp2
    assert fp1["bidiAuditV1/codepoint"] == "U+202E"
    assert fp1["bidiAuditV1/range"] == "1:6"
    assert fp1["bidiAuditV1/ruleId"] == "bidi/dangerous-span"
    assert len(fp1["bidiAuditV1/sha256"]) == 64  # sha256 hex digest
    # distinct finding types in one record get distinct hashes
    text2 = RLO + "bad.exe"
    rid = _post(client, text2, "z").json()["id"]
    hashes = {r["partialFingerprints"]["bidiAuditV1/sha256"]
              for r in _run(_sarif(client, rid).json())["results"]}
    assert len(hashes) == 2


def test_sarif_fingerprint_changes_with_filename(client):
    text = RLO + "evil" + PDF
    a = _post(client, text, "a.txt").json()["id"]
    b = _post(client, text, "b.txt").json()["id"]
    fa = _run(_sarif(client, a).json())["results"][0]["partialFingerprints"]
    fb = _run(_sarif(client, b).json())["results"][0]["partialFingerprints"]
    assert fa["bidiAuditV1/sha256"] != fb["bidiAuditV1/sha256"]
    # but the codepoint/range/rule ingredients are filename independent
    for key in ("bidiAuditV1/codepoint", "bidiAuditV1/range",
                "bidiAuditV1/ruleId"):
        assert fa[key] == fb[key]


# --------------------------------------------------------------- stability --

def test_sarif_output_is_deterministic(client):
    audit_id = _post(client, RLO + "a" + PDF + LRI + "b").json()["id"]
    first = _sarif(client, audit_id).content
    second = _sarif(client, audit_id).content
    assert first == second
    # results sorted by document position
    run = json.loads(first)["runs"][0]
    positions = [(r["locations"][0]["physicalLocation"]["region"]["startLine"],
                  r["locations"][0]["physicalLocation"]["region"]["startColumn"])
                 for r in run["results"]]
    assert positions == sorted(positions)
    # rule descriptors sorted by id
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(rule_ids)


def test_sarif_every_result_rule_is_declared(client):
    audit_id = _post(client, RLO + "x" + PDF + PDI + LRI).json()["id"]
    run = _run(_sarif(client, audit_id).json())
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in declared
        assert result["message"]["text"]
        assert result["level"] in ("none", "note", "warning", "error")
