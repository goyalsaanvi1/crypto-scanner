from pathlib import Path

from scanner.detectors.weak_hash import WeakHashDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return WeakHashDetector().scan(java_source)


def test_flags_password_hashing_as_high():
    content = (SAMPLES_DIR / "vulnerable" / "WeakHashPassword.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "WEAK_HASH"
    assert finding.severity == "HIGH"
    assert finding.line_number == 5


def test_flags_checksum_use_as_low_not_silent():
    content = (SAMPLES_DIR / "safe" / "ChecksumExample.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "WEAK_HASH"
    assert finding.severity == "LOW"
    assert finding.line_number == 5
