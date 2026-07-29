import re

from scanner.detectors.base import Detector, Finding

_GET_INSTANCE_RE = re.compile(
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*\"([^\"]*)\"", re.DOTALL
)

_WEAK_ALGORITHMS = {"MD5", "SHA1"}

_SECURITY_CONTEXT_RE = re.compile(
    r"\b(password|pwd|passwd|secret|token)\b", re.IGNORECASE
)

_CONTEXT_WINDOW_LINES = 5


class WeakHashDetector(Detector):
    """Flags MessageDigest.getInstance("MD5"/"SHA-1") calls. Always returns
    a Finding — MD5 and SHA-1 are broken hash algorithms regardless of use
    case — but calibrates severity based on nearby context: HIGH if
    variable names or comparisons within a few lines suggest the digest is
    used for password/credential verification, LOW otherwise (e.g. generic
    checksums)."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        lines = file_content.splitlines()
        for match in _GET_INSTANCE_RE.finditer(file_content):
            algorithm = match.group(1)
            normalized = algorithm.strip().upper().replace("-", "")
            if normalized not in _WEAK_ALGORITHMS:
                continue

            line_number = file_content.count("\n", 0, match.start()) + 1
            window_start = max(0, line_number - 1 - _CONTEXT_WINDOW_LINES)
            window_end = min(len(lines), line_number + _CONTEXT_WINDOW_LINES)
            context = "\n".join(lines[window_start:window_end])

            if _SECURITY_CONTEXT_RE.search(context):
                severity = "HIGH"
                message = (
                    f"MessageDigest.getInstance(\"{algorithm}\") uses "
                    f"{algorithm} in what looks like a security-sensitive "
                    "context (a password/credential-related name or "
                    "comparison nearby). MD5 and SHA-1 are broken for "
                    "security-sensitive hashing; use a proper password "
                    "hash (bcrypt, scrypt, or Argon2) for credentials, or "
                    "HMAC-SHA256 if this is for message integrity/"
                    "authentication instead."
                )
            else:
                severity = "LOW"
                message = (
                    f"MessageDigest.getInstance(\"{algorithm}\") uses "
                    f"{algorithm}, which is cryptographically broken and "
                    "unsuitable for any security purpose. This usage "
                    "doesn't show signs of a security context (e.g. looks "
                    "like a checksum), so it may be fine to leave as-is, "
                    "but flagging for awareness."
                )

            findings.append(
                Finding(
                    line_number=line_number,
                    rule_id="WEAK_HASH",
                    severity=severity,
                    message=message,
                )
            )
        return findings
