# crypto-scanner

Python CLI that scans Java source files for cryptographic misuse patterns,
such as hardcoded keys and use of insecure cipher modes.

## Setup

```bash
git clone <repo-url>
cd crypto-scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m scanner.cli <path>
```

`<path>` can be a single `.java` file:

```bash
python -m scanner.cli samples/vulnerable/EcbExample.java
```

or a directory, which is walked recursively for `.java` files:

```bash
python -m scanner.cli samples/
```

Each finding is printed as:

```
<file>:<line> [<rule_id>] <severity> - <message>
```

## Architecture

Each vulnerability check is its own `Detector` subclass in
`scanner/detectors/`, implementing `scan(file_content: str) -> list[Finding]`.
The CLI runs every registered detector against each file and merges their
findings. Detectors don't share state or call into each other, so adding a
new check means adding a new file and registering it in `scanner/cli.py`,
not modifying existing detection logic.

## Detected patterns

| Rule               | Description                                                            |
|--------------------|-------------------------------------------------------------------------|
| `HARDCODED_KEY`    | A `String`/`byte[]` field named like a secret (KEY, SECRET, PASSWORD, TOKEN) assigned directly to a literal |
| `ECB_MODE`         | `Cipher.getInstance(...)` called with a transformation string containing ECB |
| `STATIC_IV`        | A hardcoded IV/nonce byte array literal passed into a `GCMParameterSpec`/`IvParameterSpec` |
| `WEAK_CIPHER`      | `Cipher.getInstance(...)` using a weak/deprecated algorithm (DES, DESede, RC4, Blowfish) |
| `INSECURE_RANDOM`  | `java.util.Random` used to fill a byte array via `nextBytes(...)` instead of `SecureRandom` |

## Running tests

```bash
pytest -v
```
