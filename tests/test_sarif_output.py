import json
from pathlib import Path

from scanner.detectors.base import Finding
from scanner.report import build_sarif_document


def test_sarif_document_structure_and_known_finding():
    findings = [
        Finding(
            line_number=5,
            rule_id="HARDCODED_KEY",
            severity="HIGH",
            message="Hardcoded secret found.",
        ),
        Finding(
            line_number=9,
            rule_id="ECB_MODE",
            severity="HIGH",
            message="ECB mode used.",
        ),
    ]
    file_findings = [(Path("samples/vulnerable/HardcodedKey.java"), findings)]

    document = build_sarif_document(file_findings)

    # Valid JSON: round-trips cleanly.
    reparsed = json.loads(json.dumps(document))
    assert reparsed == document

    assert document["$schema"]
    assert document["version"] == "2.1.0"
    assert len(document["runs"]) == 1

    run = document["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "crypto-scanner"
    assert driver["informationUri"]

    rule_ids = {rule["id"] for rule in driver["rules"]}
    assert rule_ids == {
        "HARDCODED_KEY",
        "ECB_MODE",
        "STATIC_IV",
        "WEAK_CIPHER",
        "WEAK_HASH",
        "INSECURE_RANDOM",
        "WEAK_KEY_SIZE",
        "INSECURE_TRUST_MANAGER",
        "WEAK_KDF",
    }
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]

    results = run["results"]
    assert len(results) == 2

    hardcoded_result = next(r for r in results if r["ruleId"] == "HARDCODED_KEY")
    assert hardcoded_result["level"] == "error"
    assert hardcoded_result["message"]["text"] == "Hardcoded secret found."

    location = hardcoded_result["locations"][0]["physicalLocation"]
    uri = location["artifactLocation"]["uri"]
    assert not uri.startswith("file://")
    assert uri == "samples/vulnerable/HardcodedKey.java"
    assert location["region"]["startLine"] == 5


def test_sarif_severity_mapping_to_sarif_level():
    findings = [
        Finding(line_number=1, rule_id="STATIC_IV", severity="MEDIUM", message="m"),
        Finding(line_number=2, rule_id="WEAK_HASH", severity="LOW", message="l"),
    ]
    document = build_sarif_document([(Path("Example.java"), findings)])
    results = document["runs"][0]["results"]

    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["STATIC_IV"] == "warning"
    assert levels["WEAK_HASH"] == "note"
