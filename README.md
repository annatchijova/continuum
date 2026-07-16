# Continuum

Continuum Studio is a local-first digital-legacy companion: a protected,
navigable memory for the people who matter. It combines a polished web
experience with a deterministic, auditable, encrypted core.

![Continuum Studio](https://img.shields.io/badge/status-hackathon%20prototype-173e3c)

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
Owners can capture a note or import a local `.txt`, `.md`, `.csv`, or `.json`
file after reviewing its text in the browser. Binary and PDF ingestion remains
in the existing CLI path.

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

## Hackathon session

Codex session identifier:

`019f685f-ad37-70c0-9be9-990001e4e9fe`

This identifier is included for hackathon attribution and development
traceability. It is not a credential and does not grant access to the
repository or its data.

Continuum is the evolution of the Digital Legacy prototype. A person can
accumulate decades of wills, accounts, medical records, photographs, and
professional knowledge. When they are gone, their heirs inherit a disk full of
files with no map. Continuum turns that chaos into a navigable legacy: it
classifies, indexes, encrypts, and—when access conditions are met—answers
questions and delivers a prioritized guide.

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
