---
name: Missed detection (false negative)
about: GuardEnv did not report a credential it should have
title: "[FN] "
labels: ["false-negative", "rules"]
---

**Credential format**
Which provider and token format? Link to the provider's documentation if it is public.

**Synthetic example**
A fake value with the same shape. **Never paste a real credential**, even a revoked one.

```
VENDOR_TOKEN=vnd_0000000000000000000000000000000
```

**GuardEnv version and command**

```
guardenv --version
guardenv scan ... 
```

**Anything else**
Does the value appear inside a quoted assignment, a URL, a JSON field?
