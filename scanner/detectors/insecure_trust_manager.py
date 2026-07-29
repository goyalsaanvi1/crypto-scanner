import re

from scanner.detectors.base import Detector, Finding

_CHECK_TRUSTED_RE = re.compile(
    r"void\s+(?:checkClientTrusted|checkServerTrusted)\s*\([^)]*\)"
    r"\s*(?:throws\s+[\w.,\s]+)?\s*\{"
)

_VERIFY_RE = re.compile(
    r"boolean\s+verify\s*\([^)]*\)\s*\{"
)


class InsecureTrustManagerDetector(Detector):
    """Flags TLS validation that's been disabled or bypassed: an
    X509TrustManager whose checkClientTrusted/checkServerTrusted has an
    empty (or return-only) body, or a HostnameVerifier whose verify(...)
    unconditionally returns true. Both patterns disable certificate/
    hostname validation entirely, making the app vulnerable to
    man-in-the-middle attacks regardless of any other crypto used
    correctly elsewhere — a well-known real-world vulnerability pattern.
    At most one Finding is emitted per category per file, since multiple
    trivial check*Trusted methods in the same class all describe the same
    underlying trust-all TrustManager."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []

        trust_manager_finding = self._first_trivial_finding(
            file_content,
            _CHECK_TRUSTED_RE,
            self._is_trivial_check,
            (
                "checkClientTrusted/checkServerTrusted has an empty (or "
                "return-only) body, accepting every certificate chain "
                "without validation. This disables TLS certificate "
                "validation entirely, making the app vulnerable to "
                "man-in-the-middle attacks regardless of any other crypto "
                "used correctly elsewhere — a well-known real-world "
                "vulnerability pattern, not a theoretical one."
            ),
        )
        if trust_manager_finding:
            findings.append(trust_manager_finding)

        verify_finding = self._first_trivial_finding(
            file_content,
            _VERIFY_RE,
            self._is_trivial_verify,
            (
                "verify(...) unconditionally returns true with no real "
                "hostname comparison logic, accepting every hostname. "
                "This disables TLS hostname validation entirely, making "
                "the app vulnerable to man-in-the-middle attacks "
                "regardless of any other crypto used correctly elsewhere "
                "— a well-known real-world vulnerability pattern, not a "
                "theoretical one."
            ),
        )
        if verify_finding:
            findings.append(verify_finding)

        return findings

    def _first_trivial_finding(self, content, signature_re, is_trivial_fn, message):
        earliest_position = None
        for sig_match in signature_re.finditer(content):
            body, _ = self._extract_body(content, sig_match.end() - 1)
            if body is None:
                continue
            if not is_trivial_fn(self._strip(body)):
                continue
            if earliest_position is None or sig_match.start() < earliest_position:
                earliest_position = sig_match.start()

        if earliest_position is None:
            return None

        line_number = content.count("\n", 0, earliest_position) + 1
        return Finding(
            line_number=line_number,
            rule_id="INSECURE_TRUST_MANAGER",
            severity="HIGH",
            message=message,
        )

    @staticmethod
    def _extract_body(content: str, open_brace_index: int):
        depth = 0
        for i in range(open_brace_index, len(content)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    return content[open_brace_index + 1 : i], i
        return None, None

    @staticmethod
    def _strip(body: str) -> str:
        body = re.sub(r"//[^\n]*", "", body)
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
        return re.sub(r"\s+", "", body)

    @staticmethod
    def _is_trivial_check(stripped: str) -> bool:
        return stripped in ("", "return;")

    @staticmethod
    def _is_trivial_verify(stripped: str) -> bool:
        return stripped in ("returntrue;", "returntrue")
