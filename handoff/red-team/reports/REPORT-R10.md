# Red-team rounds R9-003 and R10

Branch `claude/peaceful-gauss-09l0j9`:

- `397c935` (R9-003)
- `4ebfffb` (R10)

Full suite: 580 passed.

## R9-003 (variant of R9-001): OpenAI SDK path

- **Verified against official OpenAI docs:**
  - the openai-python README, "Configuring the HTTP client": `http_client=DefaultHttpx2Client(...)`, and `follow_redirects=False` "so it cannot follow a response to another origin";
  - the openai-agents config docs.
  - `openai.github.io` was not reachable from this session, so I read the same docs from github.com.
- **Live probe with the real SDK** (openai 3.46.0, openai-agents 0.24.0):
  - Before the fix, a 307 re-POSTed the body to the redirect host. Authorization was stripped.
  - After the fix, the redirect host receives nothing.
  - Positive control: a well-behaved endpoint still narrates, and `store=False` still reaches the provider.
- **Fix:** a per-agent `OpenAIResponsesModel` bound to an `AsyncOpenAI` client that uses `DefaultAsyncHttpx2Client(follow_redirects=False)`. The HTTPS rule also applies to `OPENAI_BASE_URL`. No global `set_default_openai_client`.

## R10-001 (High, correctness): false "no information"

- **Reproduced:** `capture("Deed", "Property deed for the apartment. The original is in the blue archival folder.")` is stored as `real_estate`. The question "Where is the apartment deed?" is inferred as `legal`, so the core answered "No relevant information found".
- **Fix:** if the inferred filter yields nothing, recall runs without it, and the answer states "No match in the 'legal' category; showing results from all categories."
- **Controls:**
  - A matching category still filters.
  - Truly absent information is still reported as absent.
  - Explicit `MemoryField.recall(category=...)` stays strict (C-001).
- **Residual design debt:** two independent classifiers (question and document) with different vocabularies. Partial disagreement is still possible when the inferred category has some results but the best record is elsewhere.

## R10-002 (Medium, variant of R7-002): category and location tamper

- **Reproduced:** `UPDATE memories SET category='personal'` hid a `legal` will from category-filtered recall. Rewriting `artifact` changed the location shown to the heir. In both cases integrity reported `ok=True`.
- **Fix:** both columns are compared with the sealed index (`category`, `path`). No code path updates them after insert.

## R10-003 (Low): demo replaced an open session

- **Reproduced:** an heir calling `demo()` came back with `role: owner`, on fictional data.
- **Fix:** the demo is refused while a private session is open. Re-running it from the demo is still allowed.

## Closed without change

- **C3:** the core answer carries at most 200 chars per record, and it is the core result the model must narrate. Not a contract violation. My first probe used a flawed substring check.
- **C4:** about 42 ms of KDF per attempt. The API is no faster than an offline attack on `legacy.vault`, and it is local only after R8.
- **C5:** the heir sees the owner email; this is a product decision.

## Next candidates

| ID | Hypothesis |
|----|------------|
| C9 | Ranking manipulation through cleartext `state` (REINFORCED gives 1.5x), `last_access` (recency bonus) and `score`. These are legitimately mutable (STDP), so they cannot simply be sealed. A decoy could be promoted above a real record within top_k=6. Falsifier: N decoys promoted to REINFORCED push the target out of `ask()` results. |
| C10 | R10-001 partial variant: the inferred category has weak results, so the stronger record in another category is never considered. |
| C11 | Audit-event attribution: `STUDIO_*` events use `owner_id`, which for an heir is `owner-<hash(heir_id)>`, and `heir_id` is not normalized ("Heir-One" vs "heir-one"). |
