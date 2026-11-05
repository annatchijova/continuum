# Red-team round R8: Studio HTTP boundary

Commit: `afc1ecb` on `claude/peaceful-gauss-09l0j9`. Regression tests: `tests/test_security_r8.py` (20 tests).
Full suite: 505 passed.

## Confirmed and fixed

### R8-001 (High): cross-origin access to the local API

- **Root cause:** `continuum_web/server.py` validated neither `Host`, `Origin` nor `Content-Type`. `_read_json` parsed any body as JSON.
- **Reproduced against a live server and in real Chromium:**
  - A cross-site `text/plain` POST to `/api/ask` with `allow_narration: true` sent vault excerpts to a fake provider. This breaks the per-request opt-in contract.
  - A cross-site `no-cors` POST to `/api/capture` planted a record, confirmed in Chromium.
  - With a foreign `Host` (DNS rebinding), `/api/dashboard` returned the owner email and metadata.
- **Variants:** the cause is the same for all 11 POST routes and 2 GET API routes: lock, demo, unlock (brute force with readable result under rebinding), reset-passphrase, delete-workspace (needs the passphrase, but is brute-forceable under rebinding). The static demo server has no API, so it is not affected.
- **Fix:**
  - A loopback `Host` for the bound port is required on every request.
  - On `/api/*`, a present `Origin` must match and `Sec-Fetch-Site` must be `same-origin` or `none`.
  - POST requires `application/json`, which forces a preflight the server never approves.
  - Static pages check only `Host`, so Studio can still be opened from an external link.
- **Negative controls:** without the fix, the same tests fail and the Chromium harness plants a record. With the fix, same-origin UI and a CLI client without `Origin` keep working.

### R8-002 (Medium): stalled body freezes the app

- **Root cause:** `_run` called `_read_json()` while holding `Studio._mutex`, and the server had no socket timeout.
- **Reproduced:** a connection with `Content-Length: 50` and a 1-byte body blocked `/api/dashboard` indefinitely.
- **Fix:** the body is read before taking the mutex, and `Handler.timeout = REQUEST_TIMEOUT_SECONDS` (10 s).

## Candidates for next rounds (not yet confirmed)

| ID | Surface | Hypothesis | Falsifier |
|----|---------|------------|-----------|
| C1 | `narrator._validate_narration` | The authority-claim regex is bypassable ("you're authorized", "identity confirmed", "access is granted", other languages). It has no check against first-person impersonation of the deceased, or against invented, omitted or reordered facts. | Prompt-injected captured document makes a fake provider return each variant; check whether it is withheld. |
| C2 | `narrator.narrate` (NVIDIA path) | `urlopen` follows a 30x redirect and keeps the `Authorization: Bearer` header, even cross-host. | Fake endpoint replies 302 to a second local server; check whether it receives the key. |
| C3 | `Studio.ask` egress scope | `deterministic_answer` carries up to 300 chars per record, while excerpts are capped at 180. The 180 cap does not bound egress. | Long record; measure plaintext bytes in the provider payload. |
| C4 | `/api/unlock`, `/api/unlock-heir` | No attempt throttling (local attacker or another local process). | Time N wrong attempts; check for backoff. |
| C5 | Heir session in Studio | `snapshot()` exposes `owner_email` and the heir list to an heir. `heir_id` is not normalized or validated like the owner email. | Open as heir and inspect `/api/dashboard`. |
| C6 | `Studio.demo()` | Callable by an heir. It locks the current session and switches the workspace. Interaction with `delete_workspace` and the `safe-demo` child of a real workspace. | Heir session calls `/api/demo`; check state and audit. |
| C7 | Core (`legacy/`) | Variant sweep of R7-002 (unauthenticated cleartext metadata driving visibility): `category`, `artifact`, synaptic weights. | Edit the column in `memory.db`; check whether `verify_memory_integrity` detects it. |
