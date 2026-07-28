import re

from scanner.detectors.base import Detector, Finding

_IV_KEYWORDS = ("IV", "NONCE")

# Matches a byte[] field declaration assigned directly to an array literal,
# e.g. `private static final byte[] IV = { 0,1,2,3 };`
_FIELD_ASSIGNMENT_RE = re.compile(
    r"^\s*"
    r"(?:(?:public|private|protected|static|final|transient|volatile)\s+)*"
    r"byte\s*\[\s*\]\s+"
    r"(\w+)\s*=\s*"
    r"(\{[^}]*\})"
    r"\s*;"
)


class StaticIvDetector(Detector):
    """Flags byte[] fields whose name suggests an IV/nonce, are assigned a
    literal array, and are passed into a GCMParameterSpec/IvParameterSpec
    constructor elsewhere in the file. Reusing an IV/nonce across
    encryptions with the same key breaks the security guarantees of modes
    like GCM (and, with GCM specifically, can leak the authentication key)."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for line_number, line in enumerate(file_content.splitlines(), start=1):
            match = _FIELD_ASSIGNMENT_RE.match(line)
            if not match:
                continue

            field_name = match.group(1)
            if not any(keyword in field_name.upper() for keyword in _IV_KEYWORDS):
                continue

            if not self._used_as_iv_parameter(file_content, field_name):
                continue

            findings.append(
                Finding(
                    line_number=line_number,
                    rule_id="STATIC_IV",
                    severity="MEDIUM",
                    message=(
                        f"Field '{field_name}' is a hardcoded IV/nonce literal "
                        "used to build a GCMParameterSpec/IvParameterSpec. "
                        "Reusing the same IV/nonce across multiple encryptions "
                        "with the same key breaks the security guarantees of "
                        "modes like GCM; generate a fresh random IV/nonce for "
                        "every encryption."
                    ),
                )
            )
        return findings

    @staticmethod
    def _used_as_iv_parameter(file_content: str, field_name: str) -> bool:
        usage_re = re.compile(
            r"(?:GCMParameterSpec|IvParameterSpec)\s*\([^)]*\b"
            + re.escape(field_name)
            + r"\b[^)]*\)"
        )
        return usage_re.search(file_content) is not None
