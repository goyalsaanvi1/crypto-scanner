from pathlib import Path

from scanner.detectors.weak_kdf import WeakKdfDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return WeakKdfDetector().scan(java_source)


def test_flags_weak_pbkdf_iteration_count_and_static_salt():
    content = (SAMPLES_DIR / "vulnerable" / "WeakPbkdf.java").read_text()
    findings = _scan(content)

    assert len(findings) == 2
    for finding in findings:
        assert finding.rule_id == "WEAK_KDF"
        assert finding.severity == "MEDIUM"
        assert finding.line_number == 7


def test_no_findings_for_strong_pbkdf():
    content = (SAMPLES_DIR / "safe" / "StrongPbkdf.java").read_text()
    findings = _scan(content)

    assert findings == []
