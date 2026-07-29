from pathlib import Path

from scanner.detectors.insecure_trust_manager import InsecureTrustManagerDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _scan(java_source: str):
    return InsecureTrustManagerDetector().scan(java_source)


def test_flags_insecure_trust_manager():
    content = (SAMPLES_DIR / "vulnerable" / "InsecureTrustManager.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "INSECURE_TRUST_MANAGER"
    assert finding.severity == "HIGH"


def test_flags_insecure_hostname_verifier():
    content = (SAMPLES_DIR / "vulnerable" / "InsecureHostnameVerifier.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "INSECURE_TRUST_MANAGER"
    assert finding.severity == "HIGH"


def test_no_findings_for_proper_trust_manager():
    content = (SAMPLES_DIR / "safe" / "ProperTrustManager.java").read_text()
    findings = _scan(content)

    assert findings == []
