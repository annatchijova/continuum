# Red-team round R9: narration-provider boundary

Commit: `bbe8f74` on `claude/peaceful-gauss-09l0j9`. Regression tests: `tests/test_security_r9.py` (58 tests).
Full suite: 561 passed.

## Confirmed and fixed

### R9-001 (High): NVIDIA API key forwarded on redirect

- **Root cause:** `urllib.request.urlopen` copies `Authorization` onto redirected requests, including cross-host ones.
- **Reproduced:** a 301, 302 or 303 from the endpoint sent `Bearer nvapi-...` to the redirect target, and the target's reply was shown as narration. A 307 or 308 on POST raises in urllib, so the key does not leak there.
- **Fix:** an opener with a redirect handler that refuses every redirect. The endpoint must be HTTPS; plain HTTP is accepted only for loopback test servers.
- **Negative control:** without the fix, 7 of the transport tests fail.

### R9-002 (High): the narration output screen was bypassable

- **Root cause:** a single English/Spanish phrase regex on raw text.
- **Reproduced:** 31 of 34 probes reached the UI: synonyms, French, Cyrillic homoglyphs, zero-width characters, "I am your father", "Soy tu mamá", "Stop taking the penicillin", "sell the apartment and invest in bonds", and invented addresses, account numbers and amounts.
- **Fix:**
  - Normalization before screening (NFKC, format characters dropped, NFKD with accents stripped, confusables folded, casefold, whitespace collapsed).
  - Patterns for authority claims, impersonation and directive advice.
  - Numeric grounding: every number must appear in the question, the core result or the excerpts. Small counters up to the number of sources are allowed.
  - The instructions now require third-person narration and forbid new numbers.
- **False-positive controls:** 12 faithful narrations pass, including "your mother's recipe", "You can find...", and the demo checklist wording.

### Residual limits (honest scope)

- The screen is a heuristic, not a proof. It does not detect omission or reordering, invented proper names, or paraphrased advice outside the verb list.
- When the screen withholds narration, the deterministic result is still shown, and it is always visible beside any narration.

## Variant found, not fixed this round

| ID | Finding | Evidence | Why not fixed now |
|----|---------|----------|-------------------|
| C8 | The OpenAI Agents SDK path (openai 3.46.0, openai-agents 0.24.0, httpx2) follows redirects. It strips `Authorization` cross-host, but on a 307 it re-POSTs the full body, which carries the plaintext excerpts, to the redirect host. `OPENAI_BASE_URL` is not checked for HTTPS. | `poc_openai.py`: thief received `POST /v1/responses` with no Authorization. | `AGENTS.md` requires checking official OpenAI docs before changing OpenAI runtime code. A candidate fix is a client with `follow_redirects=False` and an HTTPS check on the base URL. |

## Remaining candidates from R8

- C3: egress scope; the deterministic answer carries up to 300 chars per record.
- C4: unlock throttling.
- C5: heir sees the owner email; `heir_id` is not normalized.
- C6: an heir can call `/api/demo`.
- C7: unauthenticated cleartext metadata in `memory.db`.
