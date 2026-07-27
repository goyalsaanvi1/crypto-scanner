from pathlib import Path

from scanner.detectors.hardcoded_keys import HardcodedKeyDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"

ENV_LOADED_KEY = """
public class Config {
    private static final String API_TOKEN = System.getenv("API_TOKEN");
}
"""

NON_MATCHING_FIELD_NAME = """
public class Greeting {
    private static final String GREETING = "hello world";
}
"""


def _scan(java_source: str):
    return HardcodedKeyDetector().scan(java_source)


def test_flags_hardcoded_key_sample():
    content = (SAMPLES_DIR / "vulnerable" / "HardcodedKey.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "HARDCODED_KEY"
    assert finding.severity == "HIGH"
    assert finding.line_number == 5


def test_no_findings_for_safe_sample():
    content = (SAMPLES_DIR / "safe" / "GcmExample.java").read_text()
    findings = _scan(content)

    assert findings == []


def test_key_loaded_from_env_is_not_flagged():
    findings = _scan(ENV_LOADED_KEY)

    assert findings == []


def test_non_matching_field_name_is_not_flagged():
    findings = _scan(NON_MATCHING_FIELD_NAME)

    assert findings == []
