import re

from scanner.detectors.base import Detector, Finding

# Matches a `Random <name> = new Random(...)` declaration. Anchored so it
# won't match `SecureRandom <name> = new SecureRandom(...)`.
_DECL_RE = re.compile(
    r"^\s*"
    r"(?:(?:public|private|protected|static|final)\s+)*"
    r"Random\s+(\w+)\s*=\s*new\s+Random\s*\("
)


class InsecureRandomDetector(Detector):
    """Flags java.util.Random instances that are used to produce raw byte
    material (via .nextBytes(...)) — a pattern typical of generating keys,
    IVs, or tokens. java.util.Random is not cryptographically secure: its
    output is predictable from a handful of samples, so any secret derived
    from it can potentially be reconstructed by an attacker. Use
    java.security.SecureRandom instead."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for line_number, line in enumerate(file_content.splitlines(), start=1):
            match = _DECL_RE.match(line)
            if not match:
                continue

            var_name = match.group(1)
            if not self._used_to_fill_bytes(file_content, var_name):
                continue

            findings.append(
                Finding(
                    line_number=line_number,
                    rule_id="INSECURE_RANDOM",
                    severity="HIGH",
                    message=(
                        f"'{var_name}' is a java.util.Random used to fill a "
                        "byte array via nextBytes(...), which looks like key/"
                        "IV/token generation. java.util.Random is not "
                        "cryptographically secure — its output is predictable "
                        "from a small number of samples; use "
                        "java.security.SecureRandom instead."
                    ),
                )
            )
        return findings

    @staticmethod
    def _used_to_fill_bytes(file_content: str, var_name: str) -> bool:
        usage_re = re.compile(
            r"\b" + re.escape(var_name) + r"\s*\.\s*nextBytes\s*\("
        )
        return usage_re.search(file_content) is not None
