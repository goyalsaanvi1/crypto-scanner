from dataclasses import dataclass


@dataclass
class Finding:
    line_number: int
    rule_id: str
    severity: str
    message: str


class Detector:
    """Base class for crypto misuse detectors."""

    def scan(self, file_content: str) -> list[Finding]:
        raise NotImplementedError
