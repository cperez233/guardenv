## What and why

<!-- The diff shows what changed. Explain why it should change. -->

## Checklist

- [ ] `pytest` passes and coverage stayed at or above 90%
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy` passes
- [ ] `cd web && npm run test -- --run && npm run typecheck && npm run lint && npm run build` pass

### If this adds or changes a detection rule

- [ ] Mirrored in **both** `guardenv/rules.py` and `web/src/engine/rules.ts`
- [ ] Detection test added to both suites
- [ ] Allowlist / false-positive test added to both suites
- [ ] All test credentials are **synthetic**
- [ ] Rule count in `README.md` updated
