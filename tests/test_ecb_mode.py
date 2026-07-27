from pathlib import Path

from scanner.detectors.ecb_mode import EcbModeDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return EcbModeDetector().scan(java_source)


def test_flags_ecb_sample():
    content = (SAMPLES_DIR / "vulnerable" / "EcbExample.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "ECB_MODE"
    assert finding.severity == "HIGH"
    assert finding.line_number == 9


def test_no_findings_for_gcm_sample():
    content = (SAMPLES_DIR / "safe" / "GcmExample.java").read_text()
    findings = _scan(content)

    assert findings == []


def test_no_findings_for_static_iv_gcm_sample():
    content = (SAMPLES_DIR / "vulnerable" / "StaticIvExample.java").read_text()
    findings = _scan(content)

    assert findings == []
