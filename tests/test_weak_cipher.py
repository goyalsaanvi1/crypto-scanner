from pathlib import Path

from scanner.detectors.weak_cipher import WeakCipherDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return WeakCipherDetector().scan(java_source)


def test_flags_des_as_high():
    content = (SAMPLES_DIR / "vulnerable" / "DesExample.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    assert findings[0].rule_id == "WEAK_CIPHER"
    assert findings[0].severity == "HIGH"


def test_flags_rc4_as_high_and_ignores_comment_mention():
    content = (SAMPLES_DIR / "vulnerable" / "Rc4Example.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    assert findings[0].rule_id == "WEAK_CIPHER"
    assert findings[0].severity == "HIGH"


def test_flags_blowfish_as_medium():
    content = (SAMPLES_DIR / "vulnerable" / "BlowfishExample.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    assert findings[0].rule_id == "WEAK_CIPHER"
    assert findings[0].severity == "MEDIUM"


def test_no_findings_for_gcm_sample():
    content = (SAMPLES_DIR / "safe" / "GcmExample.java").read_text()
    findings = _scan(content)

    assert findings == []
