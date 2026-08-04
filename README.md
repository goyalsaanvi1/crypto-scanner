# crypto-scanner

![Tests](https://github.com/goyalsaanvi1/crypto-scanner/actions/workflows/tests.yml/badge.svg)
![codecov](https://codecov.io/gh/goyalsaanvi1/crypto-scanner/branch/main/graph/badge.svg)

## Why This Project

Cryptographic misuse — hardcoded keys, ECB mode, disabled TLS validation,
and similar mistakes — is common in real Java codebases and easy to miss
in code review. crypto-scanner is a static-analysis CLI that scans Java
source for 9 categories of these misuse patterns using regex-based text
matching (no full AST parser). It's built as a portfolio project to
demonstrate that approach end-to-end: a detector architecture designed
for extension, SARIF 2.1.0 output for CI and security-tooling
integration, and a reusable GitHub Action wrapping it all for use in
other repos' pipelines.

## Detected Patterns

| Rule                     | Description                                                                                            |
|---------------------------|---------------------------------------------------------------------------------------------------------|
| `HARDCODED_KEY`           | A `String`/`byte[]` field named like a secret (KEY, SECRET, PASSWORD, TOKEN) assigned directly to a literal |
| `ECB_MODE`                | `Cipher.getInstance(...)` called with a transformation string containing ECB |
| `STATIC_IV`               | A hardcoded IV/nonce byte array literal passed into a `GCMParameterSpec`/`IvParameterSpec` |
| `WEAK_CIPHER`             | `Cipher.getInstance(...)` using a weak/deprecated algorithm — DES, DESede, or RC4 (HIGH), or Blowfish (MEDIUM) |
| `WEAK_HASH`               | `MessageDigest.getInstance(...)` using MD5/SHA-1 — HIGH if nearby naming suggests password/credential use, LOW otherwise (e.g. checksums) |
| `INSECURE_RANDOM`         | `java.util.Random` used for security-sensitive purposes — suggestive naming, or its `nextBytes`/`nextInt`/`nextLong` output feeding a key/IV/nonce/token/salt — instead of `SecureRandom` |
| `WEAK_KEY_SIZE`           | `KeyPairGenerator.initialize(...)`/`KeyGenerator.init(...)` with a literal key size below RSA 2048 / EC 224 / AES 128 |
| `INSECURE_TRUST_MANAGER`  | An `X509TrustManager` with an empty `checkClientTrusted`/`checkServerTrusted`, or a `HostnameVerifier` whose `verify(...)` unconditionally returns `true` |
| `WEAK_KDF`                | `PBEKeySpec(...)` with a literal iteration count below 10,000 and/or a hardcoded byte-array salt literal |

## Setup

For development (editable checkout, no console entry point):

```bash
git clone https://github.com/goyalsaanvi1/crypto-scanner.git
cd crypto-scanner
python -m venv venv
source venv/bin/activate
pip install -e .
```

Or install it as a package, which gives you the `crypto-scanner` command:

```bash
git clone https://github.com/goyalsaanvi1/crypto-scanner.git
cd crypto-scanner
pip install .
```

## Usage

```bash
crypto-scanner <path>
```

(equivalent to `python -m scanner.cli <path>`, which also works if you
installed with `pip install -e .` instead of a non-editable `pip install .`)

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
scanned files, `1` if any were found, or `2` if `.cryptoscanner.yml` is
malformed (see [Configuration](#configuration)) — useful for wiring into
CI as a pass/fail gate.

Pass `--format sarif` to emit a SARIF 2.1.0 JSON document instead of text
— e.g. for GitHub code scanning ingestion:

```bash
crypto-scanner --format sarif samples/ > results.sarif
```

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
raises a clear error (and exits with code `2`) rather than failing
silently.

## Suppressing Findings Inline

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

## Using This as a GitHub Action

This repo also ships as a reusable composite action, so other repos can
run it in their own CI without installing anything manually:

```yaml
- uses: goyalsaanvi1/crypto-scanner@main
  with:
    path: src/
    format: sarif
```

Inputs:

| Input              | Required | Default | Description                                |
|--------------------|----------|---------|----------------------------------------------|
| `path`             | yes      | —       | Directory or file to scan                     |
| `format`           | no       | `text`  | `text` or `sarif`                             |
| `fail-on-findings` | no       | `true`  | Fail the step if findings are present         |

Output: `findings-count` — total number of findings from the run.

## Web UI

There's also a local web UI — paste Java source or pick a sample, click
Run Scan, see findings rendered visually — for anyone who'd rather not
use a terminal. It's a FastAPI backend plus a React frontend, and it
shares the exact same detection engine as the CLI (`scanner/engine.py`),
just reached over an HTTP API instead of a direct import.

Backend (port 8000):

```bash
pip install ".[api]"
crypto-scanner-api
```

Frontend (port 5173), in a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173`. Both need to be running — the
frontend calls the backend directly at `http://localhost:8000`.

The UI includes a Rules panel — the same enable/disable and severity-override
controls as `.cryptoscanner.yml`, but as checkboxes and dropdowns instead of
a config file, sent with each scan request. The Rules panel can also export
its current state as a `.cryptoscanner.yml` file, or import one — validated
through the exact same parsing/error logic as the CLI's config loader.

Results can be exported from the UI as JSON or SARIF (same SARIF format as
`--format sarif` on the CLI) via the buttons above the findings list.

You can also upload multiple `.java` files instead of pasting a single
snippet — results are grouped per file with an aggregate severity summary,
mirroring how the CLI scans a directory.

Every scan is saved to a local SQLite database (`data/scan_history.db`,
gitignored) and shown in the "Recent Scans" panel — click a past scan to
reload its findings into the results panel, delete individual entries with
the `×` next to each row, or clear the whole history at once.

Code and findings can be copied to the clipboard directly from the UI, and
there's a light/dark theme toggle in the header (persisted across reloads).
The code editor (CodeMirror, with Java syntax highlighting) themes itself
to match.

### Running the Web UI with Docker

Instead of installing Python/Node locally, both services can run in
containers:

```bash
docker compose up --build
```

This builds the FastAPI backend (`Dockerfile`) and the React frontend
(`frontend/Dockerfile`, built with Vite and served by nginx), and starts
both — backend on `http://localhost:8000`, frontend on
`http://localhost:5173`. Scan history persists across container restarts
via a `./data` volume mount.

## Architecture

Each vulnerability check is its own `Detector` subclass in
`scanner/detectors/`, implementing `scan(file_content: str) -> list[Finding]`.
`scanner/engine.py` runs every registered detector against a file's
content, applies any `.cryptoscanner.yml` enable/disable and
severity-override rules, and filters out inline-suppressed findings —
this is the single shared path used by both the CLI (`scanner/cli.py`)
and the web UI's backend (`scanner/api.py`), so they can never drift out
of sync. Detectors don't share state or call into each other, so adding
a new check means adding a new file and registering it in
`scanner/engine.py`, not modifying existing detection logic.

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

These gaps are covered by regression tests in `tests/test_edge_cases.py`
against fixtures in `samples/edge_cases/`, confirming they behave as
documented rather than silently.

## Running Tests

```bash
pytest -v
```

With coverage (what CI runs):

```bash
pytest -v --cov=scanner --cov-report=term-missing
```
