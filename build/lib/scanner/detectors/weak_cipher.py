import re

from scanner.detectors.base import Detector, Finding

# Matches Cipher.getInstance("<transformation>") calls, capturing the
# transformation string literal. Anchored to the getInstance call so
# algorithm names appearing in comments or unrelated string literals are
# never matched.
_GET_INSTANCE_RE = re.compile(
    r"Cipher\s*\.\s*getInstance\s*\(\s*\"([^\"]*)\"", re.DOTALL
)

_SEVERITY_AND_REASON = {
    "DES": (
        "HIGH",
        "DES has a 56-bit effective key size, brute-forceable with modern "
        "hardware; use AES instead.",
    ),
    "DESEDE": (
        "HIGH",
        "DESede (3DES) has an effective security level of only ~112 bits "
        "and is vulnerable to meet-in-the-middle and birthday-bound "
        "(Sweet32) attacks; use AES instead.",
    ),
    "RC4": (
        "HIGH",
        "RC4 is a stream cipher with known keystream biases that leak "
        "plaintext, insecure regardless of key size; use AES with an "
        "authenticated mode like GCM instead.",
    ),
    "BLOWFISH": (
        "MEDIUM",
        "Blowfish's 64-bit block size makes it vulnerable to birthday-"
        "bound attacks when encrypting large amounts of data, and it's "
        "commonly misused with weak keys; prefer AES unless you have a "
        "specific reason to use Blowfish with a strong key.",
    ),
}


class WeakCipherDetector(Detector):
    """Flags Cipher.getInstance(...) calls that request a known-weak or
    discouraged algorithm: DES, DESede (3DES), RC4 (all HIGH severity —
    broken or too small a key size for modern use), and Blowfish (MEDIUM —
    not broken, but its small block size and common misuse with weak keys
    warrant caution)."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for match in _GET_INSTANCE_RE.finditer(file_content):
            transformation = match.group(1)
            algorithm = transformation.split("/", 1)[0].strip().upper()
            if algorithm not in _SEVERITY_AND_REASON:
                continue

            severity, reason = _SEVERITY_AND_REASON[algorithm]
            line_number = file_content.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    line_number=line_number,
                    rule_id="WEAK_CIPHER",
                    severity=severity,
                    message=(
                        f"Cipher.getInstance(\"{transformation}\") uses "
                        f"{algorithm}. {reason}"
                    ),
                )
            )
        return findings
