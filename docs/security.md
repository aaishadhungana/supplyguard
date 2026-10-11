# Security notes

## What is protected and how

| Concern | What the code does |
|---|---|
| Stolen or guessed passwords | Argon2id hashes, minimum 12 characters, rate-limited login |
| Account enumeration | Login returns the same error for unknown emails and wrong passwords, with a dummy hash so timing is similar. Registration does say when an email is taken, and is rate limited |
| Token forgery | HS256 JWTs with a required expiry. The app refuses to start without a 32-character secret |
| Access to other users' data | Every query filters by owner and returns 404 for IDs that aren't yours |
| Malicious uploads | Files are parsed as data and never executed. The filename must be `package-lock.json` or `requirements.txt`, UTF-8, and under 5 MB. A middleware rejects bodies over 6 MB |
| Prompt injection through advisories | Advisory text is passed as data inside JSON. The system prompt tells the model to ignore instructions in it, output must match a schema and is length-limited, and the AI has no way to write scores |
| Leaking data to the AI | Prompts contain package names, versions, advisory details and scores. They don't contain the project name, file contents, tokens or credentials |
| Secrets | Read from environment variables, never logged, never returned by the API. `.env` is git-ignored and Docker images exclude it |
| Abuse | Per-IP and per-user rate limits on login, registration, scan uploads and AI re-runs |
| Browser attacks | CSP, `X-Frame-Options`, `nosniff` and a strict referrer policy on the frontend. The API sets the same headers and disables its docs in production |
| False reassurance | If OSV can't be reached the scan fails. A missing CISA KEV list is shown as "unknown", not "not exploited" |

## Known limitations

- The JWT is stored in `sessionStorage`. A cross-site scripting bug would expose it. React escapes all text and nothing uses `dangerouslySetInnerHTML`, but an HttpOnly cookie would be safer.
- Tokens can't be revoked before they expire. Logout only clears the token in the browser.
- The rate limiter keeps counters in memory. They reset on restart, aren't shared across processes, and use the direct client address, so behind a proxy they need forwarded-address handling.
- The CSP allows inline scripts because Next.js needs them without per-request nonces.
- Starlette buffers an upload before the endpoint checks its size. The 6 MB middleware check uses the declared `Content-Length`, so a reverse proxy should enforce a body limit too.
- The free Gemini tier may use prompts to improve Google's products. Don't scan confidential projects with a free key.
- Findings depend entirely on OSV and CISA data. A vulnerability they don't list won't be reported.
- Reachability isn't analyzed, so "attack path" means "dependency chain", not "proven exploit path".

## Ideas for hardening further

Cookie-based sessions with CSRF protection, refresh tokens and revocation, Redis-backed rate limits, pinned GitHub Actions by commit SHA, container image scanning in CI, and signed SBOM output.