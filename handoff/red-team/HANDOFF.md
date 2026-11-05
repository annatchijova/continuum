# Red-Team Handoff (R8–R11 done; R12 next)

**Status:** paused on 2026-11-05. The owner will resume in about a month, from
a different account and a new session.

This folder is **not product documentation**. It holds adversarial findings, so
keep it out of the product docs, as `AGENTS.md` requires. The owner explicitly
asked for it to live in the repo so that work can continue.

Read `AGENTS.md` first. Its contracts (deterministic core, narrator-only
model, privacy and `store=False`, no impersonation, small tested changes)
governed every decision below.

## 1. Branches

| Branch | State | Purpose |
|--------|-------|---------|
| `main` | Default branch, at `8e879a7` when this was written. | Baseline. |
| `claude/peaceful-gauss-09l0j9` | 6 commits ahead of `main`, all pushed. Open PR: **annatchijova/continuum#1** (https://github.com/annatchijova/continuum/pull/1). CI was green on Python 3.11 and 3.12 when this was written. | Fixes from rounds R8–R11. **Do not add new rounds here.** Only push to it to answer review comments on PR #1. |
| `claude/red-team-r12` | Branched from the tip of `claude/peaceful-gauss-09l0j9` (`f44cab9`). Its only commit is this handoff. | Where R12 and later rounds continue. |

### If PR #1 has been merged when you return

- **Squash or rebase merge:** rebase this branch onto `main`. The R8–R11 commits are already in `main`, so drop them:

  ```bash
  git fetch origin main
  git rebase --onto origin/main f44cab9 claude/red-team-r12
  ```

- **Merge commit:** run `git rebase origin/main` (or merge `main` in). The duplicate commits disappear.

### If PR #1 is still open

Continue on `claude/red-team-r12`. Open a separate PR from it later, or after #1 merges. Never stack new rounds onto `claude/peaceful-gauss-09l0j9`.

### Commits on `claude/peaceful-gauss-09l0j9`, oldest first

| Commit | Round | Change |
|--------|-------|--------|
| `afc1ecb` | R8 | Restrict Studio API to same-origin local requests |
| `bbe8f74` | R9 | Harden narration transport and output screen |
| `397c935` | R9-003 | Keep OpenAI narration requests on the configured origin |
| `4ebfffb` | R10 | Fix inferred-category false negatives and seal category/location |
| `8d9c43a` | R11-001 | Use the inferred query category as a hint, not a filter |
| `f44cab9` | R11-002 | Match heirs by normalized identifier and admit only registered heirs |

## 2. Method used in every round (keep it)

1. **Hypothesis with a falsifier.** State what would prove the candidate wrong before testing it.
2. **Reproduce against the real thing:**
   - a live `ThreadingHTTPServer` for Studio;
   - real Chromium through Node Playwright (the Python package is not installed; `require('playwright')` works from Node);
   - the real OpenAI SDK, in a throwaway venv outside the repo;
   - local fake providers.
3. **Variant sweep.** Once a root cause is confirmed, search for every other place with the same cause, and fix it at the shared boundary instead of per call site.
4. **Regression test first, and watch it fail.** Tests go in `tests/test_security_rN.py`. The module docstring describes each finding (ID, severity, root cause, fix). A test that passes before the fix is broken; this happened in R8-002 and R9-003 and was corrected.
5. **Negative controls.** Re-run the attack with the fix stashed to show the test catches it. Add allowed cases so a fix cannot pass by over-blocking.
6. **Fix minimally, then run the full suite:**

   ```bash
   python3 -m pytest -q
   ```

7. **Write it up:**
   - a neutral `CHANGELOG.md` entry under `[Unreleased] / Fixed` (behavior, not exploit detail);
   - update `KNOWN_LIMITATIONS.md` when a limit changes;
   - the full write-up goes in `handoff/red-team/reports/`.
8. **Commit and push.** One commit per round or finding. The message explains the root cause and the fix.

### Environment notes from the last session

- `pytest` was not preinstalled: run `python3 -m pip install pytest hypothesis`. The suite was **597 passed** at `f44cab9`.
- A push sometimes failed with `remote rejected ... fatal error in commit_refs_rules`. It succeeded on retry. Retry with backoff, then confirm with `git fetch` and `git status -sb`.
- `openai.github.io` was **not reachable** from the session network. The Agents SDK docs were read from `github.com/openai/openai-agents-python/blob/main/docs/`, and the openai-python README from github.com.
- `AGENTS.md` requires checking OpenAI docs before any OpenAI runtime change. Do it again, because the SDK moves fast. At the time of writing it was openai 3.46.0 and openai-agents 0.24.0, the HTTP client package was `httpx2`, and the client class was `DefaultAsyncHttpx2Client`.

## 3. Findings so far

Full write-ups are in `reports/REPORT-R8.md` through `REPORT-R11.md`. The PoC scripts are in `poc/rN/`. Run them from the repo root:

```bash
python3 -I handoff/red-team/poc/r11/c11.py
```

`poc/r9/poc_openai*.py` need a venv with `openai-agents` installed.

### Fixed

| ID | Sev. | Area | Root cause | Fix |
|----|------|------|-----------|-----|
| R8-001 | High | `continuum_web/server.py` | No `Host`, `Origin` or `Content-Type` checks. Cross-site pages could force narration egress, plant captures, or lock the session; DNS rebinding could read the API. | Loopback `Host` for the bound port; matching `Origin`; `Sec-Fetch-Site` on `/api/*`; POST must be `application/json`. Static pages check `Host` only. |
| R8-002 | Med | `server.py` | The body was read while holding the session mutex, with no socket timeout. | Read the body before taking the mutex; `Handler.timeout = 10`. |
| R9-001 | High | `continuum_web/narrator.py` | `urlopen` forwarded `Authorization` on a cross-host 301/302/303. | An opener that refuses all redirects; HTTPS required (HTTP only for loopback). |
| R9-002 | High | `narrator.py` | The output screen was one regex; 31 of 34 probes passed. | Unicode normalization and confusable folding; authority, impersonation and advice patterns; numeric grounding against the evidence. A heuristic, so the core result is always shown. |
| R9-003 | Med | `narrator.py` | The OpenAI SDK re-POSTed the excerpts on a 307 to another host. | Per-agent `OpenAIResponsesModel` with an `AsyncOpenAI` client using `follow_redirects=False`; `OPENAI_BASE_URL` must be HTTPS. |
| R10-001 / R11-001 | High | `legacy/agent/query_engine.py` | The question's inferred category was a hard filter. Classifier disagreement caused false "no information" answers, or hid the best record behind weak in-category matches. | One unfiltered recall; the category only breaks exact ties and labels the answer when every result belongs to it. Explicit `MemoryField` filters stay strict (C-001 from R3). |
| R10-002 | Med | `memory_agent.verify_memory_integrity` | Cleartext `category` and `artifact` in `memory.db` could be rewritten undetected. | Both are compared with the sealed index. |
| R10-003 | Low | `Studio.demo()` | It replaced any open session; an heir came back as the demo's owner. | Refused while a private session is open. |
| R11-002 | Med | `memory_agent.open_heir/revoke_heir` | Raw-string heir matching; a revoked heir could enter with different case or spacing; unregistered ids were accepted. | Trimmed, casefolded matching; only registered heirs once any are registered; KL-011 updated. |

### Closed without change (with evidence)

| ID | Why |
|----|-----|
| C3 | The core answer carries at most 200 chars per record, and it is the core result the model must narrate. |
| C4 | About 42 ms of KDF per unlock attempt. The local API is no faster than an offline attack on `legacy.vault`, and it is loopback-only after R8. |
| C5 | The heir sees the owner email; this is a product decision. |
| C9 | Ranking via cleartext `state`/`last_access` reorders only near-ties: decoys went 0.153 → 0.205 while the target stayed at 0.876. Per-id promotion attribution would false-flag older consolidated workspaces. Pinned by `test_c9_*`. |

## 4. What to do next: R12, the filesystem boundary

None of these have been examined yet. They are hypotheses, not findings.

| Candidate | Target | Hypothesis | Falsifier |
|-----------|--------|-----------|-----------|
| C13 | `legacy/vault/artifact_store.py` `restore()` and `memory_agent.restore_artifact()` | The destination path is caller-chosen. Check traversal, following a pre-existing symlink at the destination, silent overwrite, and non-atomic writes leaving plaintext partials. | Restore into a directory where the target name is a symlink to an outside file; check whether the outside file changes. |
| C14 | `artifact_store.py` storage layout | Artifacts are named by content hash. Check whether the hash in a path or the CLI argument is validated (`../`, non-hex), and whether the restore check binds hash ↔ ciphertext ↔ AAD. | Restore with `artifact_hash="../../x"`; swap two `.enc` files and check whether both still restore. |
| C15 | `legacy/agent/export_bundle.py` | What exactly goes into the heir bundle: plaintext, keys, the audit DB? Can a crafted record (filename or content) inject paths or content into the bundle? | Export with a record titled `../../evil` and inspect the archive member names. |
| C16 | `legacy/cli.py` (1122 lines, never reviewed) | Passphrase handling (argv vs prompt, echo, env), file permissions of created files, and paths taken from the CLI. | `ps` during a CLI run; `stat` of `legacy.vault`, `*.db` and exported files. |
| C12 | `query_engine.py` | Residual classifier disagreement now affects only wording (labels, LIST intent), not selection. | Low priority. |

Suggested order: C13 → C14 → C15 → C16. The restore path writes plaintext to disk, so it carries the most risk.

## 5. Open decisions for the owner

- **Review the behavior changes in PR #1 before merging:**
  - the inferred category no longer filters;
  - vaults with registered heirs reject unknown heir ids;
  - the Studio API returns 403 or 415 to cross-origin or non-JSON requests.
- **R9-002 is a heuristic screen.** It does not detect omission, reordering, invented names, or paraphrased advice outside its verb list. A stronger design (for example, sentence-level grounding) would be a separate, reviewed change.
