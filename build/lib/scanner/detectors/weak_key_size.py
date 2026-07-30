import re

from scanner.detectors.base import Detector, Finding

# (generator class, algorithm) -> (minimum safe bits, recommendation)
_THRESHOLDS = {
    ("KeyPairGenerator", "RSA"): (2048, "ideally 3072+"),
    ("KeyPairGenerator", "EC"): (224, "ideally 256+"),
    ("KeyGenerator", "AES"): (128, "ideally 256"),
}

_INIT_METHOD = {
    "KeyPairGenerator": "initialize",
    "KeyGenerator": "init",
}

# Matches `KeyPairGenerator <name> = KeyPairGenerator.getInstance("RSA")`
# (or KeyGenerator/AES), associating a variable with the algorithm it was
# created with.
_DECL_RE = re.compile(
    r"\b(KeyPairGenerator|KeyGenerator)\s+(\w+)\s*=\s*\1"
    r"\s*\.\s*getInstance\s*\(\s*\"([^\"]+)\""
)


class WeakKeySizeDetector(Detector):
    """Flags KeyPairGenerator.initialize(<n>)/KeyGenerator.init(<n>) calls
    that use a key size below modern safe thresholds (RSA < 2048, EC < 224,
    AES < 128). Tracks which algorithm a generator variable was created
    with via getInstance(...) and matches it to a later initialize()/init()
    call on that same variable, within the same file. Only flags calls
    whose key-size argument is a literal integer; variable/constant
    references aren't resolved."""

    def scan(self, file_content: str) -> list[Finding]:
        findings = []
        for decl_match in _DECL_RE.finditer(file_content):
            generator_type, var_name, algorithm = decl_match.groups()
            algorithm = algorithm.strip().upper()

            threshold_key = (generator_type, algorithm)
            if threshold_key not in _THRESHOLDS:
                continue
            threshold, recommendation = _THRESHOLDS[threshold_key]

            method = _INIT_METHOD[generator_type]
            call_re = re.compile(
                r"\b" + re.escape(var_name) + r"\s*\.\s*" + method
                + r"\s*\(\s*(\d+)\b"
            )
            for call_match in call_re.finditer(file_content):
                key_size = int(call_match.group(1))
                if key_size >= threshold:
                    continue

                line_number = file_content.count("\n", 0, call_match.start()) + 1
                findings.append(
                    Finding(
                        line_number=line_number,
                        rule_id="WEAK_KEY_SIZE",
                        severity="MEDIUM",
                        message=(
                            f"'{var_name}' initializes a {algorithm} key "
                            f"with {key_size} bits, below the safe minimum "
                            f"of {threshold} bits for {algorithm} "
                            f"({recommendation})."
                        ),
                    )
                )
        return findings
