import re

from scanner.detectors.base import Detector, Finding

_SECURITY_KEYWORDS = ("KEY", "IV", "NONCE", "TOKEN", "SALT", "SECRET", "SECURE")

# Matches a `Random <name> = new Random(...)` declaration. Anchored so it
# won't match `SecureRandom <name> = new SecureRandom(...)`.
_DECL_RE = re.compile(
    r"^\s*"
    r"(?:(?:public|private|protected|static|final)\s+)*"
    r"Random\s+(\w+)\s*=\s*new\s+Random\s*\("
)


class InsecureRandomDetector(Detector):
    """Flags java.util.Random instances used in a way that suggests
    security-sensitive randomness: either the Random variable itself is
    named suggestively (secureRandom, keyGen, tokenGen, ...) or its output
    (via nextBytes(...) / nextInt(...) / nextLong(...)) populates a
    variable named like a key, IV, nonce, token, salt, or secret.
    java.util.Random is silent for plain non-security use (shuffling,
    picking a random message) and never flags java.security.SecureRandom,
    which is the correct API."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for line_number, line in enumerate(file_content.splitlines(), start=1):
            match = _DECL_RE.match(line)
            if not match:
                continue

            var_name = match.group(1)
            reason = self._security_signal(file_content, var_name)
            if reason is None:
                continue

            findings.append(
                Finding(
                    line_number=line_number,
                    rule_id="INSECURE_RANDOM",
                    severity="HIGH",
                    message=(
                        f"'{var_name}' is a java.util.Random {reason}. "
                        "java.util.Random is not cryptographically secure — "
                        "its output is predictable and seedable, and it "
                        "isn't designed to resist prediction attacks; use "
                        "java.security.SecureRandom instead for any "
                        "security-sensitive randomness."
                    ),
                )
            )
        return findings

    @staticmethod
    def _is_security_named(name: str) -> bool:
        upper = name.upper()
        return any(keyword in upper for keyword in _SECURITY_KEYWORDS)

    def _security_signal(self, file_content: str, var_name: str) -> str | None:
        if self._is_security_named(var_name):
            return "whose own name suggests security-sensitive use"

        escaped = re.escape(var_name)

        next_bytes_re = re.compile(
            escaped + r"\s*\.\s*nextBytes\s*\(\s*(\w+)\s*\)"
        )
        for m in next_bytes_re.finditer(file_content):
            if self._is_security_named(m.group(1)):
                return f"used via nextBytes(...) to fill '{m.group(1)}'"

        next_value_re = re.compile(
            r"(\w+)\s*=\s*" + escaped + r"\s*\.\s*next(?:Int|Long)\s*\("
        )
        for m in next_value_re.finditer(file_content):
            if self._is_security_named(m.group(1)):
                return f"used via next...() to populate '{m.group(1)}'"

        return None
