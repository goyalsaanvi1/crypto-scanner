from pathlib import Path

from scanner.detectors.static_iv import StaticIvDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return StaticIvDetector().scan(java_source)


def test_flags_static_iv_sample():
    content = (SAMPLES_DIR / "vulnerable" / "StaticIvExample.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "STATIC_IV"
    assert finding.severity == "MEDIUM"
    assert finding.line_number == 6


def test_no_findings_for_random_iv_sample():
    content = (SAMPLES_DIR / "safe" / "GcmExample.java").read_text()
    findings = _scan(content)

    assert findings == []
