import re

from scanner.detectors.base import Detector, Finding

_MIN_ITERATIONS = 10000

_NEW_PBEKEYSPEC_RE = re.compile(r"new\s+PBEKeySpec\s*\(")

_INLINE_BYTE_ARRAY_LITERAL_RE = re.compile(r"^(?:new\s+byte\s*\[\s*\]\s*)?\{")


class WeakKdfDetector(Detector):
    """Flags weak PBEKeySpec usage: a literal iteration count below 10,000,
    and/or a salt argument that resolves to a hardcoded byte-array literal
    rather than one generated via SecureRandom. Only literal integer
    iteration counts and directly-traceable salt declarations are
    evaluated; variable/constant references that can't be resolved within
    the file are a known limitation, not a bug."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for call_match in _NEW_PBEKEYSPEC_RE.finditer(file_content):
            args_text, _ = self._extract_call_args(file_content, call_match.end() - 1)
            if args_text is None:
                continue

            args = self._split_top_level(args_text)
            if len(args) < 3:
                continue

            line_number = file_content.count("\n", 0, call_match.start()) + 1

            iteration_arg = args[2].strip()
            if re.fullmatch(r"\d+", iteration_arg):
                iteration_count = int(iteration_arg)
                if iteration_count < _MIN_ITERATIONS:
                    findings.append(
                        Finding(
                            line_number=line_number,
                            rule_id="WEAK_KDF",
                            severity="MEDIUM",
                            message=(
                                "PBEKeySpec is initialized with an "
                                f"iteration count of {iteration_count}, far "
                                "below modern guidance. OWASP recommends at "
                                "least 600,000 iterations for PBKDF2-HMAC-"
                                "SHA256 (or a comparably high count for "
                                "other hash functions); a low iteration "
                                "count makes brute-force/dictionary attacks "
                                "on password hashes much faster."
                            ),
                        )
                    )

            salt_arg = args[1].strip()
            if self._is_static_salt(file_content, salt_arg):
                findings.append(
                    Finding(
                        line_number=line_number,
                        rule_id="WEAK_KDF",
                        severity="MEDIUM",
                        message=(
                            f"PBEKeySpec's salt ('{salt_arg}') is a "
                            "hardcoded/static byte array literal rather "
                            "than randomly generated. A fixed salt defeats "
                            "the purpose of salting: precomputed rainbow "
                            "tables become viable again, and identical "
                            "passwords produce identical derived keys "
                            "across users. Generate a fresh salt per "
                            "password with SecureRandom."
                        ),
                    )
                )

        return findings

    @staticmethod
    def _extract_call_args(content: str, open_paren_index: int):
        depth = 0
        for i in range(open_paren_index, len(content)):
            if content[i] == "(":
                depth += 1
            elif content[i] == ")":
                depth -= 1
                if depth == 0:
                    return content[open_paren_index + 1 : i], i
        return None, None

    @staticmethod
    def _split_top_level(args_text: str) -> list[str]:
        args = []
        depth = 0
        current = []
        for ch in args_text:
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            if ch == "," and depth == 0:
                args.append("".join(current))
                current = []
            else:
                current.append(ch)
        args.append("".join(current))
        return args

    @staticmethod
    def _is_static_salt(content: str, salt_arg: str) -> bool:
        if _INLINE_BYTE_ARRAY_LITERAL_RE.match(salt_arg):
            return True
        if re.fullmatch(r"\w+", salt_arg):
            decl_re = re.compile(
                r"\bbyte\s*\[\s*\]\s+" + re.escape(salt_arg)
                + r"\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{[^}]*\}\s*;"
            )
            return decl_re.search(content) is not None
        return False
