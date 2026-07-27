# crypto-scanner

Python CLI tool that scans Java source files for cryptographic misuse patterns
(e.g. ECB mode usage, hardcoded keys).

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m scanner.cli <path>
```

`<path>` may be a single `.java` file or a directory, which will be walked
recursively for `.java` files.

## Status

Skeleton only — file discovery works, but no detection rules are implemented
yet.
