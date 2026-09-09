# Contributing to GuardEnv

Thanks for helping make GuardEnv better. This document covers the parts that are
specific to this project; everything else is ordinary GitHub workflow.

## Getting set up

```bash
git clone https://github.com/cperez233/guardenv
cd guardenv
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install

cd web && npm install
```

## Before you open a pull request

```bash
pytest --cov=guardenv --cov-report=term-missing
ruff check . && ruff format --check .
mypy

cd web && npm run test -- --run && npm run typecheck && npm run lint && npm run build
```

CI runs exactly these, plus a Docker build and a self-scan. Coverage must stay at
or above 90%.

## Adding a detection rule

A rule lives in two places and must be added to both, or the CLI and the
playground will disagree about what counts as a secret.

1. **`guardenv/rules.py`** — append a `_rule(...)` entry to `RULES`:

   ```python
   _rule(
       "vendor-token",                     # kebab-case, stable, never renamed
       "Vendor API Token",
       "One sentence a reader can act on.",
       Severity.CRITICAL,
       r"\b(?P<secret>vnd_[A-Za-z0-9]{32})\b",
       keywords=("vnd_",),                 # lowercase; the prefilter needs this
       tags=("vendor", "saas"),
       allowlist=_DOC_SAMPLES,
   ),
   ```

2. **`web/src/engine/rules.ts`** — mirror it, with the `g` flag on the pattern and
   `(?<secret>…)` as the capture group name.

3. **Tests, in both suites** — one case proving the rule fires on a synthetic
   credential, and one proving it does *not* fire on the vendor's documentation
   sample or on an obvious placeholder.

### Rule quality bar

- **Every rule needs a `secret` capture group.** Reporters read it to redact the
  value; the ruleset integrity tests fail without it.
- **Keywords must be lowercase and as selective as you can make them.** They are
  the prefilter, and the prefilter is most of the scanner's performance budget.
- **Prefer a distinctive prefix over a length constraint.** `vnd_` plus 32
  characters is a good rule; "32 base62 characters" on its own is not — it will
  match half of every lockfile you ever scan.
- **Rules without a distinctive shape need `entropy_min`.** That is what keeps
  the generic assignment rules from reporting `password = "changeme"`.
- **Severity reflects blast radius, not confidence.** A key that can move money
  or grant repository write access is `CRITICAL`; a key that identifies an
  environment is `INFO`.

## Test credentials

Never commit a real credential, even a revoked one — it will end up in git
history, in forks, and in every clone.

Build synthetic values instead. Where a provider embeds a checksum, generate a
valid one: `tests/conftest.py` has `make_github_token()`, which computes the CRC32
that GitHub's format requires, so the validator tests measure something real.

## Reporting a security issue

Please do not open a public issue for a vulnerability in GuardEnv itself. Use
GitHub's private vulnerability reporting on the repository's Security tab.

If GuardEnv **missed** a credential in your repository, that is an ordinary bug —
open an issue with a synthetic example of the format it failed to detect.

## Commit and PR conventions

- One logical change per pull request.
- Explain *why* in the description; the diff already shows *what*.
- Update the README's rule count if you added or removed a rule.
