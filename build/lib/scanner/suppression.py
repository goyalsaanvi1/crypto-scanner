import re

from scanner.detectors.base import Finding

# Matches `// cryptoscanner: ignore RULE_ID` or the bare
# `// cryptoscanner: ignore` (suppresses every rule on that line).
_DIRECTIVE_RE = re.compile(r"//\s*cryptoscanner:\s*ignore(?:\s+(\w+))?")


def _parse_directives(file_content: str) -> dict[int, set[str] | None]:
    """Maps each suppressed line number to either a set of rule_ids to
    suppress, or None to suppress every rule on that line. A directive
    applies to the line it's on (same-line placement) and the line right
    after it (prior-line placement)."""
    suppressions: dict[int, set[str] | None] = {}

    def add(line_number: int, rule_id: str | None) -> None:
        if line_number not in suppressions:
            suppressions[line_number] = None if rule_id is None else {rule_id}
        elif suppressions[line_number] is not None:
            if rule_id is None:
                suppressions[line_number] = None
            else:
                suppressions[line_number].add(rule_id)
        # else: already suppressing everything on this line, nothing to add

    for line_number, line in enumerate(file_content.splitlines(), start=1):
        match = _DIRECTIVE_RE.search(line)
        if not match:
            continue
        rule_id = match.group(1)
        add(line_number, rule_id)

        # Only a standalone comment line (nothing but whitespace before
        # the "//") counts as a "prior line" directive for the next line.
        # A trailing same-line directive applies only to its own line.
        if line[: match.start()].strip() == "":
            add(line_number + 1, rule_id)

    return suppressions


def filter_suppressed_findings(file_content: str, findings: list[Finding]) -> list[Finding]:
    """Filters out any Finding whose line has a matching (or bare)
    `// cryptoscanner: ignore` directive on the same line or the line
    immediately before it."""
    suppressions = _parse_directives(file_content)

    result = []
    for finding in findings:
        if finding.line_number in suppressions:
            rule_ids = suppressions[finding.line_number]
            if rule_ids is None or finding.rule_id in rule_ids:
                continue
        result.append(finding)
    return result
