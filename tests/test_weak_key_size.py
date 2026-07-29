from pathlib import Path

from scanner.detectors.weak_key_size import WeakKeySizeDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return WeakKeySizeDetector().scan(java_source)


def test_flags_weak_rsa_key_size():
    content = (SAMPLES_DIR / "vulnerable" / "WeakRsaKey.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "WEAK_KEY_SIZE"
    assert finding.severity == "MEDIUM"
    assert finding.line_number == 6


def test_no_findings_for_strong_rsa_key_size():
    content = (SAMPLES_DIR / "safe" / "StrongRsaKey.java").read_text()
    findings = _scan(content)

    assert findings == []
