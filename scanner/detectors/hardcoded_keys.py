import re

from scanner.detectors.base import Detector, Finding

_SECRET_KEYWORDS = ("KEY", "SECRET", "PASSWORD", "TOKEN")

# Matches a String/byte[] field declaration assigned directly to a literal,
# e.g. `private static final String SECRET_KEY = "abc123";`
_FIELD_ASSIGNMENT_RE = re.compile(
    r"^\s*"
    r"(?:(?:public|private|protected|static|final|transient|volatile)\s+)*"
    r"(?:String|byte\s*\[\s*\])\s+"
    r"(\w+)\s*=\s*"
    r'("(?:[^"\\]|\\.)*"|\{[^}]*\})'
    r"\s*;"
)


class HardcodedKeyDetector(Detector):
    """Flags String/byte[] fields whose name suggests a secret and whose
    value is a literal assigned directly in source, rather than loaded
    from a method call, another variable, config, or the environment."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for line_number, line in enumerate(file_content.splitlines(), start=1):
            match = _FIELD_ASSIGNMENT_RE.match(line)
            if not match:
                continue

            field_name = match.group(1)
            if not any(keyword in field_name.upper() for keyword in _SECRET_KEYWORDS):
                continue

            findings.append(
                Finding(
                    line_number=line_number,
                    rule_id="HARDCODED_KEY",
                    severity="HIGH",
                    message=(
                        f"Field '{field_name}' looks like a cryptographic secret "
                        "assigned directly to a literal value. Hardcoded secrets "
                        "in source code can be extracted from decompiled bytecode "
                        "or version control history; load secrets from a secure "
                        "store, config, or environment variable instead."
                    ),
                )
            )
        return findings
