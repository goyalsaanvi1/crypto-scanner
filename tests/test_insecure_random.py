from pathlib import Path

from scanner.detectors.insecure_random import InsecureRandomDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return InsecureRandomDetector().scan(java_source)


def test_flags_insecure_random_key():
    content = (SAMPLES_DIR / "vulnerable" / "InsecureRandomKey.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "INSECURE_RANDOM"
    assert finding.severity == "HIGH"
    assert finding.line_number == 5


def test_secure_random_is_not_flagged():
    content = (SAMPLES_DIR / "safe" / "SecureRandomExample.java").read_text()
    findings = _scan(content)

    assert findings == []


def test_non_security_random_use_is_not_flagged():
    content = (SAMPLES_DIR / "safe" / "RandomShuffleExample.java").read_text()
    findings = _scan(content)

    assert findings == []
