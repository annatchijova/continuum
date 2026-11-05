# Red-team round R11

Commit: `8d9c43a` on `claude/peaceful-gauss-09l0j9`. Regression tests: `tests/test_security_r11.py` (8 tests).
Full suite: 588 passed.

## R11-001 (High, correctness): the inferred category hid the best record

- **Reproduced:**
  - One record: "Safe deposit box key: the bank safe deposit box key is in the kitchen drawer." It is stored as `unknown`.
  - Six bank notes, stored as `financial`.
  - The query "safe deposit box key bank" infers `financial`. Filtered recall returned only the six notes. The answering record (unfiltered score 0.926 vs 0.153) never appeared.
- **Why R10-001 missed it:** the R10 fallback applied only when the inferred category had zero results.
- **Fix:** a single unfiltered recall. Recall mutates STDP state, so it runs once. The inferred category only breaks exact score ties. The answer gets a category label only when every result belongs to it. When no result does, the answer says so.
- **Intentional semantics change:** my own R10 test that pinned strict filtering became a "matching category ranks first" test. Explicit `MemoryField.recall(category=...)` stays strict (C-001 in R3).

## C9 (closed, Low): ranking through cleartext state and recency

- **Measured:** six decoys set to REINFORCED with fresh `last_access`, and the target set to `last_access=0`. Decoy scores went from 0.153 to 0.205; the target dropped from 0.926 to 0.876 and stayed first.
- **Bound:** the 1.5x multiplier plus a recency bonus of at most 0.05 can reorder only near-ties.
- **Not fixed:** per-id promotion attribution, the analogue of R7-002, would flag every workspace consolidated before that logging existed. The cost is not justified at this impact.
- A test pins the bound, so a future scoring change re-opens the question.

## Methodology note

My first two C9 probes were invalid, and I discarded them:

- The two-wills baseline already had the "attacker-preferred" order before any tamper.
- In the seven-record baseline, the target was already absent before any tamper.

Debugging that second absence is what surfaced R11-001.

## Next candidates

| ID | Hypothesis |
|----|------------|
| C11 | CONFIRMED (probe `c11.py`): after `revoke_heir("heir-one")` with an inactivity policy, `open_heir` denies "heir-one" but grants "Heir-One", "heir-one " and "never-registered". Revocation matches the raw string, and any unregistered id is accepted. Within KL-011, a passphrase holder can already use the owner path, so this is not a crypto bypass. But `revoke_heir` promises denial, and the audit records the access under an unrelated actor. Decision needed: enforce at the logical layer, or document. |
| C12 | Two independent classifiers: residual disagreement still affects the answer *label* and the LIST intent wording, not selection. Low. |
