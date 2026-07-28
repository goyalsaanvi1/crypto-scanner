from pathlib import Path

from scanner.detectors.insecure_random import InsecureRandomDetector

SAMPLES_DIR = Path(__file__).parent.parent / "samples"

NON_CRYPTO_RANDOM_USE = """
import java.util.Random;

public class Dice {
    public static int roll() {
        Random random = new Random();
        return random.nextInt(6) + 1;
    }
}
"""

SECURE_RANDOM_USE = """
import java.security.SecureRandom;

public class KeyGen {
    public static byte[] generateKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16];
        random.nextBytes(key);
        return key;
    }
}
"""


def _scan(java_source: str):
    return InsecureRandomDetector().scan(java_source)


def test_flags_insecure_random_sample():
    content = (SAMPLES_DIR / "vulnerable" / "InsecureRandomExample.java").read_text()
    findings = _scan(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "INSECURE_RANDOM"
    assert finding.severity == "HIGH"
    assert finding.line_number == 7


def test_no_findings_for_gcm_sample():
    content = (SAMPLES_DIR / "safe" / "GcmExample.java").read_text()
    findings = _scan(content)

    assert findings == []


def test_random_used_without_nextbytes_is_not_flagged():
    findings = _scan(NON_CRYPTO_RANDOM_USE)

    assert findings == []


def test_secure_random_is_not_flagged():
    findings = _scan(SECURE_RANDOM_USE)

    assert findings == []
