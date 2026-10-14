# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Playground folder scan reads up to 2,000 files in parallel and scans them in
  batches with a progress bar, then filters to files with findings.
- The entropy chart's threshold value sits in its own gutter, so it never
  covers a point on narrow screens.
- A Spanish entry page at `/es` with its own Open Graph image and metadata;
  the URL path follows the language switch.

## [1.1.0] - 2026-10-14

### Added

- **Encoded secrets** — base64 values (Kubernetes Secrets, Docker auth,
  "obfuscated" constants) are decoded and their plaintext scanned with the
  signature rules; findings are reported at the encoded value. On by default,
  `--no-decode` turns it off. The playground runs the same pass.
- **Four new signatures** — `supabase-access-token`, `cloudflare-api-token`,
  `vercel-token` and `discord-webhook` (52 rules in total).
- **Playground** — diff mode (added vs. removed lines, per-file attribution),
  folder scan, one-click redaction with undo, A–F risk grade, provider-specific
  fix guides, false positives exported as a CLI-compatible baseline, a Protect
  panel (`.gitignore`, `.env.example`, pre-commit, GitHub Actions), shareable
  links, English/Spanish and a dark theme.
- **Releases** — tagged releases publish the wheel and sdist as GitHub release
  assets; PyPI publishing is gated behind the `PYPI_PUBLISH` repository variable.

### Fixed

- The playground was missing eight of the CLI's rules (Azure AD client secret,
  Datadog, Discord bot, GitLab runner, Braintree, PyPI, both Twilio rules). Both
  rulesets are identical again, and a test now fails if they drift.
- The test suite no longer calls `os.geteuid()` on Windows.

## [1.0.0] - 2026-09-09

First stable release.

### Added

- **Signature engine** — 48 deterministic rules covering AWS, GCP, Azure,
  DigitalOcean, GitHub (classic, fine-grained, OAuth and app tokens), GitLab,
  Stripe, Square, Braintree, OpenAI, Anthropic, Hugging Face, Slack, Discord,
  Telegram, Twilio, SendGrid, Mailgun, Shopify, npm, PyPI, HashiCorp Vault,
  Terraform Cloud, Datadog, PEM and PuTTY private keys, JWTs, and connection
  strings for PostgreSQL, MySQL, MongoDB, Redis, AMQP and HTTP basic auth.
- **Entropy engine** — Shannon entropy with per-charset thresholds (hex, base64,
  base64url, alphanumeric, mixed) and ten structural heuristics that suppress
  UUIDs, ISO timestamps, semver, file paths, hostnames, SRI hashes, CSS colours,
  numeric literals, word-like identifiers, low-variety strings, repeated runs and
  documentation placeholders.
- **Checksum validation** — GitHub tokens are verified against the base62 CRC32
  they embed, and matching findings are marked `verified`.
- **Deduplication** — overlapping detections collapse to the most specific one:
  vendor rule > generic shape rule > entropy.
- **Scanner** — concurrent-capable traversal with intelligent directory and
  extension exclusions, a documented `.gitignore` subset, binary sniffing that
  respects UTF-16/32 BOMs, a five-encoding decode fallback, file-size caps, and
  per-file error isolation.
- **CLI** — `scan`, `rules` and `entropy` commands built on Typer with `rich`
  output, standardised exit codes (`0` clean, `1` secrets, `2` error), stdin
  support, rule/severity filtering and an adjustable entropy threshold.
- **Reporters** — `rich` terminal tables, GuardEnv JSON, SARIF 2.1.0 with
  `security-severity` and `partialFingerprints` for GitHub Code Scanning, and
  `::error` workflow annotations.
- **Baselines** — `--write-baseline` / `--baseline` to acknowledge existing
  findings so CI fails only on new ones.
- **Playground** — a React 18 + TypeScript + Tailwind single-page app that ports
  the engine to the browser: split-view editor and audit inspector, a Shannon
  threshold simulator with a per-token entropy scatter plot, three analysis
  modes, and JSON/SARIF/Markdown export. Runs fully offline.
- **Distribution** — a multi-stage Alpine Docker image running as a non-root
  user, four `.pre-commit-hooks.yaml` hook ids, and a CI matrix across Python
  3.10-3.12 on Linux plus 3.12 on macOS and Windows.

### Performance

- Replaced the per-rule, per-line keyword prefilter with a two-stage design that
  tests each unique keyword once per document and re-checks only the survivors
  per line. Throughput on the benchmark corpus went from 0.7 MB/s to 4.3 MB/s
  (6x) with no change in detection behaviour.
- Binary sniffing now counts non-text bytes with `bytes.translate` rather than a
  Python loop (~15%).
- Line-offset indexes are built with `itertools.accumulate` and only when a
  document-scoped rule actually matches.
- `ScanOptions.workers` now defaults to `1`. Detection is CPU-bound Python that
  holds the GIL, and the benchmark measured thread pools as consistently slower
  (521 files/s serial versus 448 files/s with four threads).

[1.1.0]: https://github.com/cperez233/guardenv/releases/tag/v1.1.0
[1.0.0]: https://github.com/cperez233/guardenv/releases/tag/v1.0.0
