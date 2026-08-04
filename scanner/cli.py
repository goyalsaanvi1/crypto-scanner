import sys
from pathlib import Path

import click

from scanner.config import ConfigError, load_config
from scanner.engine import run_all_detectors
from scanner.report import print_findings, print_sarif


def find_java_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix == ".java" else []
    return sorted(target.rglob("*.java"))


@click.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Print 'No findings' for scanned files with zero findings.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "sarif"]),
    default="text",
    help="Output format: text (default) or sarif.",
)
def main(path: Path, verbose: bool, output_format: str) -> None:
    """Scan .java files under PATH for cryptographic misuse patterns.

    Looks for a .cryptoscanner.yml config file in the current working
    directory to enable/disable rules or override their severity.

    Exits 0 if no findings were produced, 1 if any findings were found.
    """
    try:
        config = load_config(Path.cwd())
    except ConfigError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(2)

    any_findings = False
    file_findings = []
    for java_file in find_java_files(path):
        content = java_file.read_text()
        findings = run_all_detectors(content, config)
        if findings:
            any_findings = True

        if output_format == "text":
            print_findings(java_file, findings, verbose=verbose)
        else:
            file_findings.append((java_file, findings))

    if output_format == "sarif":
        print_sarif(file_findings)

    sys.exit(1 if any_findings else 0)


if __name__ == "__main__":
    main()
