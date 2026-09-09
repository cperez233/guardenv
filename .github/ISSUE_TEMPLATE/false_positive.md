---
name: False positive
about: GuardEnv reported something that is not a credential
title: "[FP] "
labels: ["false-positive", "rules"]
---

**Rule that fired**
The `ruleId` from the report, e.g. `generic-secret-assignment` or `high-entropy-string`.

**The reported value**
Redacted is fine — GuardEnv's own output is already redacted. What *kind* of value is it (a hash, an identifier, a build id)?

**Minimal input that reproduces it**

```
```

**Output**

```
guardenv scan file --json
```

**Why it is not a credential**
One or two sentences. If it is a recognisable class of value (a checksum format, an identifier scheme), say which — that is usually what turns into a heuristic.
