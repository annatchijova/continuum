# Continuum

*A private, cryptographically verifiable memory for the people you love.*

Licensed under the [Apache License 2.0](LICENSE).

![Continuum Studio](https://img.shields.io/badge/status-hackathon%20prototype-173e3c)

## The problem, stated plainly

When someone dies, the people who loved them inherit two things at once: grief,
and a hard drive. Wills, insurance policies, medical history, the password to
the account that pays the mortgage, the one photo that explains a family
story no document ever recorded — all of it sits scattered across files,
folders, and devices, with no map and no order. Nobody grieving should also
have to become a forensic investigator of their own family's life.

The easy answer — "just point an AI at all the files and let people ask
questions" — trades one problem for a worse one. A model that can quietly
misread a document, invent a detail, or decide on its own who gets access to
what is not trustworthy with a will, a diagnosis, or a house deed. Grief is
not the moment to introduce a system that might be confidently wrong.

Continuum's answer is to separate the two jobs. A deterministic, encrypted,
audited core decides what exists, what it means, and who may see it. An AI —
used only with explicit, per-request consent — may put that already-decided
answer into gentle, human language. It is never asked to decide anything.
The people left behind deserve clarity delivered with warmth, but the clarity
itself has to be provable, not just plausible.

## Works without an API key

Continuum's core product requires no API key, cloud account, or model access.
The owner can create and lock a vault, capture and encrypt memories, classify
and retrieve evidence, verify the audit chain, configure access conditions,
and use the owner and heir flows entirely offline. An OpenAI API key is needed
only for the optional, per-request GPT-5.6 narration layer; disabling it never
changes a source, ranking, access decision, or integrity result.

## What Continuum actually does

- **Understands a lifetime of documents.** Ingests text and classifies it by
  domain (legal, medical, financial, property, professional, personal,
  credentials, and more) with a deterministic rule-based classifier — no
  model guesses at what a document *is*.
- **Answers questions with sources, not vibes.** `legacy query "where is the
  house contract?"` returns a ranked, cited answer from the owner's own
  material. Every answer can show exactly which document produced it.
- **Remembers the way people do.** A TF-IDF + STDP-inspired memory field
  reinforces what gets recalled often and lets what doesn't fade toward
  `FORGOTTEN` — never deleted, always auditable, never silently erased.
- **Speaks only when invited to.** With `OPENAI_API_KEY` set and explicit,
  per-question opt-in, GPT-5.6 may narrate the core's already-selected
  evidence in plain language. It cannot unlock a vault, choose what counts as
  evidence, rank a result, or grant access to anyone.
- **Hands the household down safely.** Owners define heirs and the exact
  condition that releases access to them — an inactivity period, a fixed
  date, a pre-shared key, or a manual switch — evaluated locally, by the
  core, never by a model.
- **Survives the worst-case scenario.** If the owner cannot ever be reached
  again, Shamir Secret Sharing lets `K` of `N` trusted people reconstruct
  access together, while any `K-1` of them learn nothing. Nobody holds the
  whole key alone.

## The ethical line: AI narrates, it never decides

This is not a slogan; it is an architectural boundary enforced in code and
tested directly:

- The deterministic core selects, ranks, classifies, and grants access
  *before* any model is ever called. A model receives only the
  already-decided answer and the excerpts the core chose — never raw,
  unfiltered access to the vault.
- Narration is opt-in per question, stateless, untraced (SDK tracing and
  response storage are both disabled), and explicitly instructed to narrate
  only what it was given — never to invent, reorder, omit, or add a fact,
  and never to claim an access decision it did not make.
- Swapping the narrator off changes only the *wording* of an answer, never
  its *sources* or *whether it was allowed*. If a change to the narrator
  could ever change a decision, that would be treated as a defect in the
  architecture, not an acceptable trade-off.
- The audit trail records that narration happened and how many sources were
  involved — never the sensitive question itself, and never the narrated
  text. Privacy holds even in the system's own logbook.

## Try the product

```bash
python3 -m continuum_web.server --workspace .continuum-demo
```

Open `http://127.0.0.1:8787`, then choose **Explore a safe demo**. This creates
only fictional data in the workspace supplied to `--workspace`. For the full
demo script, architecture, and OpenAI integration boundary, see
[HACKATHON.md](HACKATHON.md).

The Studio uses no web-framework dependency. The original CLI remains fully
available below for direct vault management.

Studio has separate owner and heir entry points. Heir access delegates to the
existing policy-aware core path and is intentionally read-only in the UI.
When creating a Studio workspace, the owner must explicitly choose an heir
release condition: an inactivity period or the deliberately marked no-policy
option. The UI never silently assigns a release policy.
Owners can capture a note or import a local `.txt`, `.md`, `.csv`, or `.json`
file after reviewing its text in the browser. Binary and PDF ingestion remains
in the existing CLI path.

New Studio workspaces enable the core's `memory.db` encryption before the first
capture and archive each captured text in the encrypted artifact store. Existing
vaults retain their current configuration; use `legacy encrypt-db` to migrate
an older vault deliberately.

## Optional ChatGPT narration

Set `OPENAI_API_KEY` and install the optional Agents SDK to enable GPT-5.6
narration over locally retrieved evidence. A person must also explicitly tick
the consent control in the UI. The core determines retrieval and access, while
the agent only explains the sources already selected; the narration request is
stateless and disables SDK tracing.

```bash
export OPENAI_API_KEY='...'
pip install -e '.[agents]'
python3 -m continuum_web.server
```

## Design principles

- **Deterministic.** Classification, scoring (`Fraction` arithmetic, with no
  floats in decisions), and the Heir Guide produce the same output for the
  same input. An LLM may narrate results, but never decide them.
- **Auditable.** Every operation is sealed in an append-only hash chain
  (SHA-256 plus optional HMAC). `verify_legacy.py` is stdlib-only and can be
  given to heirs or auditors to verify the chain without installing anything.
- **Encrypted.** The legacy index lives in an AES-256-GCM vault
  (PBKDF2-SHA256, 260k iterations). Raw files can optionally be archived in
  the content-addressed encrypted `ArtifactStore`.

## Architecture

The current prototype package is still named `legacy`; the package rename is a
later implementation step.

```
legacy/
├── core/       canonicalization, hash chain, audit trail, custody, time-lock,
│               database encryption, and process locking
├── ingestion/  document taxonomy and deterministic classifier
├── memory/     TF-IDF + STDP memory field and consolidation
├── knowledge/  encrypted professional-knowledge extractor
├── vault/      AES-GCM vault, encrypted artifact store, access conditions
└── agent/      owner/heir orchestration, queries, guide, doctor, export
```

## Quickstart

```bash
pip install -e ".[dev,memory]"   # installs the `legacy` command

# Create a vault with a 90-day inactivity condition
legacy init --inactivity-days 90

# Ingest documents (classify, index, and audit)
legacy ingest ~/Documents --knowledge

# Store an encrypted copy of a critical file
legacy archive ~/Documents/will.pdf

# Query in natural language
legacy query "where is the house contract?"

# Generate the Heir Guide
legacy guide --output guide.md

# Add and revoke heirs
legacy heir-add maria_daughter --name "Maria" --with-key
legacy heir-revoke maria_daughter

# Export and verify a portable heir bundle
legacy export ~/legacy_for_maria
legacy bundle-verify ~/legacy_for_maria

# Rotate the passphrase, encrypt databases, and run health checks
legacy rekey
legacy encrypt-db
legacy doctor
legacy verify
```

## Custody and recovery

The central product scenario is that the passphrase dies with the owner.
Shamir Secret Sharing distributes a recovery key among `N` custodians so that
**any `K` can reconstruct it while `K-1` learn nothing**. This is a mathematical
guarantee over GF(2⁸), not a promise made by application logic.

```bash
# Five custodians; three are required
legacy custody setup --shares 5 --threshold 3

# Check configuration without a passphrase
legacy custody status

# Recover using hidden interactive share prompts
legacy custody recover --set-passphrase --actor olga
```

Passphrase rotation (`rekey`) does not invalidate shares: vault v2 uses
independent keyslots. Re-running `custody setup` does revoke the previous
custodian set.

An optional offline time-lock puzzle provides a third recovery path:

```bash
legacy custody calibrate --days 30
legacy custody timelock-setup --squarings 260000000000
legacy custody timelock-recover --set-passphrase --actor olga
```

The time-lock imposes a sequential computational work floor, not a wall-clock
date. See `KNOWN_LIMITATIONS.md` before relying on it.

## Security model

| Guarantee | Mechanism |
|---|---|
| Legacy index confidentiality | AES-256-GCM vault v2 with independent keyslots |
| Archived-file confidentiality and integrity | GCM plus SHA-256 content addressing |
| Database confidentiality at rest | Application-level AES-GCM field encryption, opt-in via `encrypt-db` |
| Recovery after passphrase loss | K-of-N Shamir custody |
| Safe passphrase rotation | Keyslot rewrapping without re-encrypting the payload |
| Tamper-evident operations | SHA-256 hash chain; HMAC resists chain recomputation |
| No silent CLI instance collision | Cooperative `AgentLock` |

The system does not promise semantic contradiction detection, entity
resolution, atomicity across separate SQLite databases, or a cryptographic
wall-clock time-lock. These limitations are documented with IDs and rationale
in [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md). Read it before trusting
real data.

## Earned the hard way: seven rounds of internal red-team

Trust in a system that guards wills and medical records cannot rest on a
README's word. Before Continuum carried its current name, its predecessor
went through seven documented internal red-team rounds — each one abducting
a plausible failure mode, deducing a concrete, checkable consequence, and
confirming it by induction against the live code before calling it fixed.
Every round below shipped a fix and a regression test; nothing was patched by
softening a test until it passed.

| Round | Scope | Representative findings |
|---|---|---|
| R1 | Internal baseline sweep, 8 findings | TOCTOU hash divergence on in-memory content; symlink traversal in directory ingestion; a non-constant-time passphrase comparison in the CLI |
| R2 | Memory & audit semantics, 10 findings | Non-atomic vault sealing (a crash mid-`seal()` could strand the legacy); reinforce/forget with no auth or audit trail; silent semantic contradictions never surfaced to anyone |
| R3 | Cryptographic consistency, 6 findings | `memory.db` living outside the chain of trust; unbounded score growth overflowing to `float('inf')`; a store-plus-audit atomicity gap |
| R4 | Vault sealing | `seal()` failing open: a *wrong* passphrase could silently replace the vault and destroy custody |
| R5 | Ciphertext structure | In-band signaling — the ciphertext's own prefix was valid, exploitable plaintext |
| R6 | Search index | A legacy FTS5 search index surviving encryption with the plaintext still readable inside it |
| R7 | Access policy & suppression | A second heir's key silently locking out every heir; an attacker able to flip a memory to `FORGOTTEN` outside the audit trail, invisible to both the heir and the integrity check |

The R7 fixes are the two most recent, and both now ship with dedicated
regression tests in `tests/test_security_r7.py`:

- **Multi-heir lockout.** Access conditions default to requiring *every*
  listed condition. Under the naive reading, registering a second heir's key
  made the vault unopenable by *any* heir — the worst possible moment to
  discover a lockout is after the owner is gone. Heir keys now form their own
  OR-group: any registered heir's own key satisfies that part of the policy,
  while the group still participates in whatever AND/OR the owner configured
  for the other conditions.
- **Invisible suppression.** A memory's `state` governs whether an heir can
  ever see it again, but that field is unauthenticated metadata. Someone with
  raw filesystem access to `memory.db` could flip a memory to `FORGOTTEN`
  without the heir noticing and without the integrity check catching it. The
  check now cross-references every `FORGOTTEN` memory against the audit
  trail; a suppression with no matching `MEMORY_FORGOTTEN` event is flagged
  as tampering, not silently trusted.

This is why the security posture in this README is a claim about a system
that has been attacked on paper, repeatedly, by its own builders — not a
claim about a system nobody has yet tried to break.

## Tests

```bash
python -m pytest -q
```

## Environment variables

| Variable | Effect |
|---|---|
| `LEGACY_DATA_DIR` | Data directory (default `~/.legacy`) |
| `LEGACY_OWNER_ID` | Owner identifier |
| `LEGACY_HMAC_KEY` | Hex HMAC key for the audit trail (recommended: at least 32 bytes) |
| `LEGACY_HMAC_KEY_FILE` | Alternative path to a file containing the key bytes |

## Hackathon session

Codex session identifier:

`019f685f-ad37-70c0-9be9-990001e4e9fe`

This identifier is included for hackathon attribution and development
traceability. It is not a credential and does not grant access to the
repository or its data.
