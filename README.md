<div align="center">

# GuardEnv

**Catch leaked credentials before they reach your remote.**

A fast, dependency-light secret scanner that pairs deterministic vendor signatures with Shannon entropy analysis — plus a browser playground that runs the same engine entirely offline.

[![CI](https://github.com/guardenv/guardenv/actions/workflows/ci.yml/badge.svg)](https://github.com/guardenv/guardenv/actions/workflows/ci.yml)
[![CodeQL](https://github.com/guardenv/guardenv/actions/workflows/codeql.yml/badge.svg)](https://github.com/guardenv/guardenv/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12%20|%203.13-3776AB?logo=python&logoColor=white)](https://pypi.org/project/guardenv/)
[![License: MIT](https://img.shields.io/badge/license-MIT-10b981.svg)](LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-f43f5e.svg)](CONTRIBUTING.md)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-fab040?logo=pre-commit&logoColor=white)](.pre-commit-hooks.yaml)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-6366f1.svg)](https://docs.github.com/code-security/code-scanning)

</div>

---

## What it does

GuardEnv reads a source tree — or stdin, or a pasted snippet in the browser — and reports credentials that should never have been committed: cloud keys, git-forge tokens, payment and AI provider keys, private key material, and database URIs with inline passwords.

Two detectors run side by side:

| Detector | Answers | Strength | Weakness |
| --- | --- | --- | --- |
| **Signatures** (48 regex rules) | *"Is this a Stripe live key?"* | Names the credential type and the provider; near-zero false positives | Only finds credentials it has a pattern for |
| **Entropy** (Shannon, per charset) | *"Is this string too random to be code?"* | Catches bespoke and unknown token formats | Noisy on its own — hashes, UUIDs and minified code all score high |

The interesting engineering is in making the second one usable. Raw entropy flags every lockfile hash and base64 image in a repository. GuardEnv runs a set of cheap structural heuristics *before* the threshold comparison — UUIDs, ISO timestamps, semver, file paths, hostnames, SRI hashes, word-like identifiers, low-variety strings and documentation placeholders are all recognised and dropped. When both detectors fire on the same bytes, the more specific finding wins, so a report never says "high entropy string" about something it could have called "AWS access key".

---

## Quick start

### CLI

```bash
pip install guardenv
```

```bash
guardenv scan .                       # scan the working tree
guardenv scan src/ --fail-on HIGH     # only HIGH+ fails the run
guardenv scan --stdin < config.yaml   # scan a stream
git diff --cached | guardenv scan --stdin --stdin-name staged.diff
```

```
╭──────────────────────────── GuardEnv scan report ────────────────────────────╮
│                                                                              │
│  Target      examples                                                        │
│  Files       3 scanned, 0 skipped, 1.9 KB read                               │
│  Duration    8.7 ms (214.7 KB/s)                                             │
│  Findings    6 CRITICAL  ·  3 HIGH                                           │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Docker

```bash
docker build -t guardenv .
docker run --rm -v "$PWD:/workspace:ro" guardenv scan .
```

The image is a two-stage Alpine build that ships only a virtualenv and runs as an unprivileged user. Mount your tree read-only — the scanner never writes to it.

### Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/guardenv/guardenv
    rev: v1.0.0
    hooks:
      - id: guardenv
```

Four hook ids are provided: `guardenv` (staged files, fails on `MEDIUM`+), `guardenv-strict` (fails on anything), `guardenv-baseline` (fails only on findings absent from `.guardenv-baseline.json`), and `guardenv-repo` (whole tree).

### GitHub Actions

```yaml
- run: pip install guardenv
- run: guardenv scan . --sarif --output guardenv.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: guardenv.sarif
```

Findings land in the Security tab as Code Scanning alerts, with `partialFingerprints` so GitHub tracks the same leak across commits instead of reopening it.

---

## Architecture

```mermaid
flowchart TB
    subgraph inputs [" "]
        direction LR
        FS["Source tree"]
        STDIN["stdin / pipe"]
        WEB["Pasted text<br/>(browser)"]
    end

    subgraph core ["Core engine"]
        direction TB
        WALK["scanner.py<br/><i>traversal · gitignore · binary sniff · encoding fallback</i>"]
        subgraph detectors ["Detectors"]
            direction LR
            RULES["rules.py<br/><i>48 signatures<br/>two-stage keyword prefilter</i>"]
            ENT["entropy.py<br/><i>Shannon per charset<br/>benign-shape heuristics</i>"]
        end
        DEDUP["deduplicate_findings()<br/><i>specific rule &gt; generic rule &gt; entropy</i>"]
    end

    subgraph outputs ["Reporters"]
        direction LR
        TTY["rich table<br/><i>exit 0 / 1 / 2</i>"]
        JSON["JSON report"]
        SARIF["SARIF 2.1.0<br/><i>Code Scanning</i>"]
        BASE["baseline.json"]
    end

    FS --> WALK
    STDIN --> WALK
    WEB -.->|"identical engine,<br/>ported to TypeScript"| detectors
    WALK --> RULES
    WALK --> ENT
    RULES --> DEDUP
    ENT --> DEDUP
    DEDUP --> TTY
    DEDUP --> JSON
    DEDUP --> SARIF
    DEDUP --> BASE
```

```
guardenv/
├── guardenv/
│   ├── models.py       Severity ladder, Finding, ScanSummary, redaction, fingerprints
│   ├── entropy.py      Shannon kernel, charset classification, benign-shape heuristics
│   ├── rules.py        48 signatures, keyword index, checksum validators, deduplication
│   ├── scanner.py      Traversal, .gitignore subset, binary sniffing, encoding fallback
│   ├── reporters.py    rich tables, JSON, SARIF 2.1.0, GitHub annotations
│   ├── baseline.py     Acknowledge existing findings so CI only fails on new ones
│   └── cli.py          Typer interface, exit codes
├── web/                React + TypeScript playground (the same engine, client-side)
├── tests/              222 tests
└── scripts/benchmark.py
```

---

## The playground

`web/` is a React 18 + TypeScript + Tailwind single-page app that reimplements the engine in TypeScript so it runs with **no backend and no network calls**. Paste a `.env` file or drop one in; findings appear as you type.

```bash
cd web && npm install && npm run dev
```

- **Split view** — an editor with a line-number gutter that marks affected lines by severity, next to an audit inspector with severity badges, analysis time in milliseconds and per-finding detail.
- **Entropy simulator** — a slider over the Shannon threshold (3.0 → 6.0) with a scatter plot of every candidate token in the document. Tokens above the line are flagged; tokens drawn with a dashed outline cleared the threshold but were dropped by a heuristic, so you can see *why* something was not reported.
- **Analysis modes** — signatures only, entropy only, or both.
- **Export** — copy or download the report as GuardEnv JSON or SARIF 2.1.0, byte-compatible with what the CLI emits.

The TypeScript port is not a reimplementation-by-eye: `web/src/engine/engine.test.ts`'s 81 tests pin the same expectations as the Python suite (same entropy values, same charset thresholds, same benign-shape reasons, same rule ids), so the two engines cannot drift apart silently.

---

## Benchmark

Reproducible with `python scripts/benchmark.py`. The corpus is synthetic — 2,000 Python files of benign-looking source with credentials planted in 2% of them.

```
GuardEnv 1.0.0 · Python 3.12.3 · Linux x86_64
Corpus: 2,000 files · 240,000 lines · 8.8 MB · 37 planted secrets
Best of 5 runs

configuration            seconds     files/s      MB/s   findings
-----------------------------------------------------------------
regex only                 2.060         971       4.3         37
entropy only               1.999       1,000       4.4         24
combined                   3.839         521       2.3         37
combined, 4 threads        4.463         448       2.0         37
```

Measured on an **Intel Core i5-4200U @ 1.60 GHz** (2013 dual-core ultrabook part) — a deliberately modest machine, so treat these as a floor rather than a headline. Run the script on your own hardware for numbers that mean something to you.

Two results worth reading carefully:

**Extra threads make it slower.** Detection is CPU-bound Python holding the GIL, so a thread pool adds contention without adding parallelism — 521 files/s serial versus 448 files/s with four threads. `ScanOptions.workers` therefore defaults to `1`. Raise it with `--workers` only when reads genuinely dominate (network mounts, cold storage), and measure before you do.

**The prefilter was the whole story.** Profiling the first working version showed the regex engine barely registering, while ~57% of wall time went to a Python-level `any(keyword in line for keyword in rule.keywords)` executed once per rule per line — roughly 1.4M calls per 30k lines. Replacing it with a two-stage design (test each *unique* keyword once against the whole document, then re-check only the survivors per line) took the scanner from 0.7 MB/s to 4.3 MB/s, a **6×** improvement with no change to what it detects. Counting non-text bytes with `bytes.translate` instead of a Python loop was worth another 15%.

---

## CLI reference

```
guardenv scan [PATHS...]     scan files, directories or stdin
guardenv rules               list the ruleset (--json, --tag)
guardenv entropy TOKEN       score one string and explain the verdict
```

### Exit codes

| Code | Meaning |
| :--: | --- |
| `0` | Clean — no findings at or above the failure threshold |
| `1` | Secrets found |
| `2` | Execution error — bad arguments, unknown rule id, unreadable baseline, I/O failure |

### `guardenv scan`

| Flag | Description |
| --- | --- |
| `--stdin`, `--stdin-name NAME` | Read the document from stdin under a chosen path label |
| `--json` / `--sarif` | Machine-readable report on stdout (mutually exclusive) |
| `-o`, `--output FILE` | Write the report to a file instead of stdout |
| `--github-annotations` | Emit `::error file=…` workflow commands for inline PR annotations |
| `--fail-on SEVERITY` | Minimum severity that exits `1` (default `MEDIUM`) |
| `--fail-on-warning` | Exit `1` on any finding, including `INFO` |
| `--min-severity SEVERITY` | Drop findings below this severity from the report entirely |
| `-e`, `--entropy-threshold N` | Absolute Shannon threshold in bits/char, applied to every charset |
| `--no-entropy` / `--no-rules` | Run a single detector |
| `--no-heuristics` | Disable benign-shape suppression (expect noise; useful for triage) |
| `-r`, `--rule ID` / `--exclude-rule ID` | Select or disable rules by id (repeatable; unknown ids exit `2`) |
| `--exclude-dir NAME` / `--exclude GLOB` / `--include GLOB` | Narrow the traversal |
| `--max-file-size BYTES` | Skip files above this size (default 5 MB) |
| `--no-gitignore` | Ignore the repository's `.gitignore` |
| `--follow-symlinks` | Follow symlinked files and directories (off by default) |
| `-j`, `--workers N` | Worker threads (default `1`; see the benchmark notes) |
| `--baseline FILE` / `--write-baseline FILE` | Acknowledge existing findings; fail only on new ones |
| `--show-secrets` | Include unredacted values in the report |
| `-q`, `--quiet` / `--no-banner` | Quieten the terminal output |

### Baselines

Adopting a scanner on a repository that already has findings is the usual blocker. Record them once, then let CI fail only on what is new:

```bash
guardenv scan . --write-baseline .guardenv-baseline.json   # exits 0
guardenv scan . --baseline .guardenv-baseline.json         # exits 1 only on new leaks
```

Fingerprints are `sha256(path, rule id, line, secret)` truncated to 16 hex characters. Moving a secret to a different line produces a new fingerprint — deliberately, since that is usually a re-introduction rather than the same acknowledged finding. The baseline file itself stores only redacted values.

---

## Rule matrix

GuardEnv ships **48 deterministic signatures** plus the entropy detector.

<details>
<summary><b>Cloud providers</b> — 9 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `aws-access-key-id` | AWS Access Key ID | `CRITICAL` | — |
| `aws-secret-access-key` | AWS Secret Access Key | `CRITICAL` | — |
| `azure-ad-client-secret` | Azure AD Client Secret | `CRITICAL` | — |
| `azure-storage-connection-string` | Azure Storage Connection String | `CRITICAL` | — |
| `digitalocean-token` | DigitalOcean Personal Access Token | `CRITICAL` | — |
| `gcp-oauth-client-secret` | Google OAuth Client Secret | `CRITICAL` | — |
| `gcp-service-account` | GCP Service Account Key File | `CRITICAL` | — |
| `aws-session-token` | AWS Session Token | `HIGH` | — |
| `gcp-api-key` | Google Cloud API Key | `HIGH` | — |

</details>

<details>
<summary><b>Source control & CI</b> — 7 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `github-oauth-token` | GitHub OAuth / App Token | `CRITICAL` | ✓ |
| `github-pat-classic` | GitHub Personal Access Token (classic) | `CRITICAL` | ✓ |
| `github-pat-fine-grained` | GitHub Fine-grained Personal Access Token | `CRITICAL` | — |
| `gitlab-pat` | GitLab Personal Access Token | `CRITICAL` | — |
| `hashicorp-vault-token` | HashiCorp Vault Token | `CRITICAL` | — |
| `terraform-cloud-token` | Terraform Cloud API Token | `CRITICAL` | — |
| `gitlab-runner-token` | GitLab Runner Registration Token | `HIGH` | — |

</details>

<details>
<summary><b>Payments & commerce</b> — 5 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `paypal-braintree-token` | Braintree Access Token | `CRITICAL` | — |
| `shopify-token` | Shopify Access Token | `CRITICAL` | — |
| `square-access-token` | Square Access Token | `CRITICAL` | — |
| `stripe-secret-key` | Stripe Secret Key | `CRITICAL` | — |
| `stripe-publishable-key` | Stripe Publishable Key | `INFO` | — |

</details>

<details>
<summary><b>AI providers</b> — 4 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `anthropic-api-key` | Anthropic API Key | `CRITICAL` | — |
| `openai-api-key` | OpenAI API Key | `CRITICAL` | — |
| `openai-api-key-legacy` | OpenAI API Key (legacy format) | `CRITICAL` | — |
| `huggingface-token` | Hugging Face Access Token | `HIGH` | — |

</details>

<details>
<summary><b>Communications & SaaS</b> — 9 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `sendgrid-api-key` | SendGrid API Key | `CRITICAL` | — |
| `slack-token` | Slack API Token | `CRITICAL` | — |
| `datadog-api-key` | Datadog API Key | `HIGH` | — |
| `discord-bot-token` | Discord Bot Token | `HIGH` | — |
| `mailgun-api-key` | Mailgun API Key | `HIGH` | — |
| `slack-webhook` | Slack Incoming Webhook | `HIGH` | — |
| `telegram-bot-token` | Telegram Bot Token | `HIGH` | — |
| `twilio-api-key` | Twilio API Key SID | `HIGH` | — |
| `twilio-account-sid` | Twilio Account SID | `MEDIUM` | — |

</details>

<details>
<summary><b>Package registries</b> — 3 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `npm-access-token` | npm Access Token | `CRITICAL` | — |
| `npmrc-auth-token` | npmrc Auth Token | `CRITICAL` | — |
| `pypi-upload-token` | PyPI Upload Token | `CRITICAL` | — |

</details>

<details>
<summary><b>Key material & sessions</b> — 3 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `private-key-block` | Cryptographic Private Key | `CRITICAL` | — |
| `putty-private-key` | PuTTY Private Key | `CRITICAL` | — |
| `json-web-token` | JSON Web Token | `MEDIUM` | — |

</details>

<details>
<summary><b>Connection strings</b> — 6 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `mongodb-connection-string` | MongoDB Connection String | `CRITICAL` | — |
| `mysql-connection-string` | MySQL Connection String | `CRITICAL` | — |
| `postgres-connection-string` | PostgreSQL Connection String | `CRITICAL` | — |
| `amqp-connection-string` | AMQP Connection String | `HIGH` | — |
| `basic-auth-url` | Credentials Embedded in URL | `HIGH` | — |
| `redis-connection-string` | Redis Connection String | `HIGH` | — |

</details>

<details>
<summary><b>Generic heuristics</b> — 2 rules</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `dotenv-secret-assignment` | Dotenv Secret Assignment | `HIGH` | — |
| `generic-secret-assignment` | Generic Secret Assignment | `MEDIUM` | — |

</details>

<details>
<summary><b>Entropy detector</b> — 1 pseudo-rule</summary>

| Rule ID | Detects | Severity | Verified |
| --- | --- | :--: | :--: |
| `high-entropy-string` | Shannon entropy above the configured threshold | `MEDIUM` | — |

</details>

Rules marked **Verified** carry a structural validator. GitHub tokens embed a base62 CRC32 checksum over their payload; GuardEnv recomputes it and marks the finding `verified` when it matches. A failed check never suppresses a finding — it only withholds the confidence boost, because a revoked or truncated token in your source tree is still a leak worth reporting.

---

## Design notes

**Redaction is the default everywhere.** Findings carry `AKIA********DNPQ`, never the raw value — in the terminal, in JSON, in SARIF snippets and in baselines. Line previews are masked too, so a report can be pasted into an issue without re-leaking what it found. `--show-secrets` exists for local triage and is never the default.

**False positives are a correctness bug.** A scanner that cries wolf gets disabled, and a disabled scanner detects nothing. Every vendor rule carries an allowlist for the sample credentials that appear in that vendor's own documentation (`AKIAIOSFODNN7EXAMPLE` and friends), the generic assignment rules reject `process.env.X`, booleans, integers and lowercase-word values, and the entropy detector runs ten structural heuristics before it compares anything to a threshold.

**Hostile inputs are the normal case.** A repository will hand a file walker broken symlinks, permission errors, 4 GB bundles, UTF-16 configs, latin-1 legacy files and genuine binaries. GuardEnv sniffs for NUL bytes (checking BOMs *first*, so UTF-16 text is not mistaken for a binary), falls back through five encodings before giving up, caps file size, and reports unreadable files as warnings in the summary and as SARIF notifications rather than aborting the run.

**One engine, two implementations, one test contract.** The playground could not reuse the Python code, so the rules, thresholds and heuristics were ported to TypeScript — and the TypeScript test suite asserts the same values as the Python one. If someone tunes a threshold in one place, the other side's tests fail.

---

## Development

```bash
pip install -e ".[dev]"

pytest --cov=guardenv --cov-report=term-missing   # 222 tests
ruff check . && ruff format --check .
mypy                                              # strict

cd web
npm install
npm run test && npm run typecheck && npm run lint && npm run build
```

CI runs the Python suite across 3.10 / 3.11 / 3.12 on Linux plus 3.12 on macOS and Windows, enforces a 90% coverage floor (currently 93%), type-checks with `mypy --strict`, lints the playground with `typescript-eslint` strict-type-checked, builds the Docker image, and has GuardEnv scan its own source tree and upload the SARIF.

The self-scan job also asserts that the fixture tree in `examples/` still exits `1` — a regression that silently stops detecting secrets would otherwise look like a green build.

---

## Limitations

Worth knowing before you rely on it:

- **Working tree only.** GuardEnv does not walk git history. A secret removed in the current commit but still reachable in an earlier one will not be reported; pair it with a history scanner for that.
- **No liveness check.** Findings are not validated against provider APIs, so a rotated key still reports as a finding. That is intentional — validating would mean sending your credentials to a third party.
- **The `.gitignore` support is a documented subset.** Comments, negation, directory-only patterns, anchoring and shell globs are handled; exotic `**` anchoring is not. Unsupported patterns simply fail to match, so the scanner errs towards scanning more, never less.
- **Single-machine throughput.** Detection is CPU-bound Python. For very large monorepos, shard by directory across CI jobs rather than reaching for `--workers`.

---

## Contributing

Adding a rule is a small, well-shaped change: append a `_rule(...)` entry to `RULES` in `guardenv/rules.py`, mirror it in `web/src/engine/rules.ts`, and add a detection test plus an allowlist test to both suites. The ruleset integrity tests will tell you if you forgot the `secret` capture group, the tags, or the lowercase keywords.

Please include a **synthetic** credential in tests — never a real one, even a revoked one.

## License

MIT — see [LICENSE](LICENSE).
