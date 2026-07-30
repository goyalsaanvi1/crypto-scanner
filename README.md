# crypto-scanner

![Tests](https://github.com/goyalsaanvi1/crypto-scanner/actions/workflows/tests.yml/badge.svg)
![codecov](https://codecov.io/gh/goyalsaanvi1/crypto-scanner/branch/main/graph/badge.svg)

Python CLI that scans Java source files for cryptographic misuse patterns,
such as hardcoded keys and use of insecure cipher modes.

## Setup

For development (editable checkout, no console entry point):

```bash
git clone <repo-url>
cd crypto-scanner
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Or install it as a package, which gives you the `crypto-scanner` command:

```bash
git clone <repo-url>
cd crypto-scanner
pip install .
```

## Usage

```bash
crypto-scanner <path>
```

(equivalent to `python -m scanner.cli <path>`, which still works too —
useful if you installed via `requirements.txt` rather than `pip install .`)

`<path>` can be a single `.java` file:

```bash
crypto-scanner samples/vulnerable/EcbExample.java
```

or a directory, which is walked recursively for `.java` files:

```bash
crypto-scanner samples/
```

Each finding is printed as:

```
<file>:<line> [<rule_id>] <severity> - <message>
```

By default, files with no findings are silent. Pass `--verbose` to print
`<file>: No findings` for those too:

```bash
crypto-scanner --verbose samples/safe/
```

The CLI exits with code `0` if no findings were produced across all
scanned files, or `1` if any were found — useful for wiring into CI as a
pass/fail gate.

Pass `--format sarif` to emit a SARIF 2.1.0 JSON document instead of text
— e.g. for GitHub code scanning ingestion:

```bash
crypto-scanner --format sarif samples/ > results.sarif
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
| `WEAK_CIPHER`      | `Cipher.getInstance(...)` using a weak/deprecated algorithm — DES, DESede, or RC4 (HIGH), or Blowfish (MEDIUM) |
| `WEAK_HASH`        | `MessageDigest.getInstance(...)` using MD5/SHA-1 — HIGH if nearby naming suggests password/credential use, LOW otherwise (e.g. checksums) |
| `INSECURE_RANDOM`  | `java.util.Random` used for security-sensitive purposes — suggestive naming, or its `nextBytes`/`nextInt`/`nextLong` output feeding a key/IV/nonce/token/salt — instead of `SecureRandom` |
| `WEAK_KEY_SIZE`    | `KeyPairGenerator.initialize(...)`/`KeyGenerator.init(...)` with a literal key size below RSA 2048 / EC 224 / AES 128 |
| `INSECURE_TRUST_MANAGER` | An `X509TrustManager` with an empty `checkClientTrusted`/`checkServerTrusted`, or a `HostnameVerifier` whose `verify(...)` unconditionally returns `true` |
| `WEAK_KDF`         | `PBEKeySpec(...)` with a literal iteration count below 10,000 and/or a hardcoded byte-array salt literal |

## Configuration

The CLI looks for a `.cryptoscanner.yml` file in the current working
directory. If it's absent, all rules run at their default severity
(current behavior). If present, it can disable specific rules or force a
rule's findings to report a different severity:

```yaml
rules:
  HARDCODED_KEY:
    enabled: true
  WEAK_HASH:
    enabled: true
    severity_override: HIGH
  ECB_MODE:
    enabled: false
```

Any rule not listed uses its default (enabled, default severity).
`enabled: false` skips that detector entirely for the run.
`severity_override` replaces the severity on every finding that rule
produces (e.g. forcing `WEAK_HASH` to always report `HIGH`, regardless of
its usual LOW/HIGH heuristic). An unknown `rule_id` or malformed YAML
raises a clear error rather than failing silently.

## Suppressing findings inline

A specific finding can be suppressed with a `// cryptoscanner: ignore
RULE_ID` comment, placed either on the same line as the flagged code or
on the line directly above it:

```java
private static final String KEY = "abc123"; // cryptoscanner: ignore HARDCODED_KEY
```

```java
// cryptoscanner: ignore HARDCODED_KEY
private static final String KEY = "abc123";
```

A bare `// cryptoscanner: ignore` (no rule ID) suppresses every finding
on that line. The rule ID must match the finding being suppressed — a
directive for a different rule (e.g. `ignore ECB_MODE` next to a
`HARDCODED_KEY` finding) has no effect. Suppressed findings are filtered
out entirely: not printed, and not counted toward the exit code.

## Known Limitations

Detectors use regex-based text matching over a single file at a time,
not a full Java AST parser or cross-file dataflow analysis. That's a
deliberate scope decision, not an oversight — catching the cases below
properly would require a real parser or dataflow tracking, which is a
meaningfully larger project than a regex-based scanner. As a result,
detectors can miss:

- Secrets built via string concatenation instead of a single string
  literal (e.g. `"abc" + "def"`)
- Cipher algorithm strings, key sizes, or iteration counts passed as a
  variable rather than an inline literal — there's no dataflow/variable
  tracking across lines

## Running tests

```bash
pytest -v
```
