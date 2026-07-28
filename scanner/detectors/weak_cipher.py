import re

from scanner.detectors.base import Detector, Finding

_WEAK_ALGORITHMS = {"DES", "DESEDE", "RC4", "BLOWFISH"}

# Matches Cipher.getInstance("<transformation>") calls, capturing the
# transformation string literal. The algorithm is whatever precedes the
# first "/" (or the whole string, for a bare transformation like "RC4").
_GET_INSTANCE_RE = re.compile(
    r"Cipher\s*\.\s*getInstance\s*\(\s*\"([^\"]*)\"", re.DOTALL
)


class WeakCipherDetector(Detector):
    """Flags Cipher.getInstance(...) calls that request a known-weak or
    deprecated algorithm: DES, DESede (triple DES), RC4, or Blowfish. These
    algorithms have small block/key sizes or structural weaknesses and
    shouldn't be used for new encryption; use AES with an authenticated
    mode like GCM instead."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for match in _GET_INSTANCE_RE.finditer(file_content):
            transformation = match.group(1)
            algorithm = transformation.split("/", 1)[0].strip().upper()
            if algorithm not in _WEAK_ALGORITHMS:
                continue

            line_number = file_content.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    line_number=line_number,
                    rule_id="WEAK_CIPHER",
                    severity="HIGH",
                    message=(
                        f"Cipher.getInstance(\"{transformation}\") uses "
                        f"{algorithm}, a weak or deprecated cipher algorithm. "
                        "DES/DESede have small key/block sizes vulnerable to "
                        "brute force and meet-in-the-middle attacks, RC4 has "
                        "known keystream biases, and Blowfish's 64-bit block "
                        "size is vulnerable to birthday-bound attacks; use "
                        "AES with an authenticated mode like GCM instead."
                    ),
                )
            )
        return findings
