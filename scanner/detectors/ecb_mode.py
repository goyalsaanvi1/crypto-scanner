import re

from scanner.detectors.base import Detector, Finding

# Matches Cipher.getInstance("<transformation>") calls, capturing the
# transformation string literal. DOTALL/re.finditer over the full content
# so the call can span multiple lines.
_GET_INSTANCE_RE = re.compile(
    r"Cipher\s*\.\s*getInstance\s*\(\s*\"([^\"]*)\"", re.DOTALL
)


class EcbModeDetector(Detector):
    """Flags Cipher.getInstance(...) calls whose transformation string
    requests ECB mode, e.g. "AES/ECB/PKCS5Padding". ECB encrypts identical
    plaintext blocks to identical ciphertext blocks, leaking structural
    patterns in the plaintext (famously visible when ECB-encrypting an
    image). Note: some JCE providers default bare "AES" (no mode specified)
    to ECB as well, but this detector only flags transformations that
    explicitly name ECB."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for match in _GET_INSTANCE_RE.finditer(file_content):
            transformation = match.group(1)
            if "ECB" not in transformation.upper():
                continue

            line_number = file_content.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    line_number=line_number,
                    rule_id="ECB_MODE",
                    severity="HIGH",
                    message=(
                        f"Cipher.getInstance(\"{transformation}\") uses ECB mode. "
                        "ECB encrypts identical plaintext blocks into identical "
                        "ciphertext blocks, leaking patterns in the plaintext; "
                        "use an authenticated mode like GCM with a random IV "
                        "instead."
                    ),
                )
            )
        return findings
