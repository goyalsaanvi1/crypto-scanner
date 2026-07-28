from pathlib import Path

from scanner.detectors.weak_cipher import WeakCipherDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return WeakCipherDetector().scan(java_source)


def test_flags_weak_cipher_sample():
    content = (SAMPLES_DIR / "vulnerable" / "WeakCipherExample.java").read_text()
    findings = _scan(content)

    assert len(findings) == 4
    algorithms_flagged = [f.line_number for f in findings]
    assert algorithms_flagged == sorted(algorithms_flagged)
    for finding in findings:
        assert finding.rule_id == "WEAK_CIPHER"
        assert finding.severity == "HIGH"


def test_no_findings_for_gcm_sample():
    content = (SAMPLES_DIR / "safe" / "GcmExample.java").read_text()
    findings = _scan(content)

    assert findings == []
