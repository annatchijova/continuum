# Continuum owner stress test

This protocol prepares a real-owner end-to-end test without putting personal
data in Git or sending plaintext to a model. It is designed for normal,
incomplete, messy personal archives.

## Safety boundary

- Work from a new directory outside this repository, for example
  `~/continuum-anna-stress/`.
- Copy sources into the test directory; do not move or rename the originals.
- Start with `OPENAI_API_KEY` unset. The deterministic product is fully
  usable without it.
- Do not include passwords, seed phrases, API keys, active recovery codes, or
  third-party material without permission.
- The question oracle is a test instrument, not vault content. Never import
  it into Continuum.

## Prepare the folder once

```text
~/continuum-anna-stress/
├── source/                  # copied files, preserving their real disorder
├── context-notes/           # owner-written .md or .txt companion notes
├── question-oracle.md       # private expected-answer checklist
└── vault/                   # created by Continuum Studio; never commit it
```

Use [stress-oracle.template.md](stress-oracle.template.md) as the starting
point for `question-oracle.md`.

## Run the local product

```bash
cd /path/to/continuum
unset OPENAI_API_KEY
python3 -m continuum_web.server --workspace ~/continuum-anna-stress/vault
```

Open `http://127.0.0.1:8787`. This is a local server only; it is not the
static preview used for judges.

Create a workspace with a strong passphrase and an explicit heir-release
policy. The Studio enables database-at-rest encryption before its first
capture.

## First batch: deliberately ordinary chaos

Use 12–20 files, not an entire lifetime at once. Preserve confusing file
names, duplicates, old versions, abbreviations, and mixed topics. Start with
the Studio-supported formats: `.txt`, `.md`, `.csv`, and `.json`.

Include a small mix of:

- a property or home note;
- subscriptions or recurring expenses;
- one health instruction that is safe to test locally;
- family archive context;
- a professional or account note;
- a duplicate or obsolete version;
- one broad, mixed-topic note;
- one nearly empty or unhelpful file.

For a scanned document or PDF, preserve the original separately for now and
add an owner-written companion note such as `deed-context.md`. Current Studio
does not claim semantic PDF, OCR, DOCX, or legacy DOC extraction.

## Capture and observe

For each imported text file, review the browser preview before protecting it.
Add tags only when they clarify an ambiguity; do not spend time manually
organizing everything. Record these facts in the private oracle:

- source filename;
- expected category, if any;
- whether the category was sensible;
- what context was missing;
- whether a duplicate was recognized;
- one question that should retrieve it.

After every small batch, use **Verify integrity**. The result should confirm
both the audit chain and memory records.

## Query evaluation

Ask the exact questions in `question-oracle.md`. Evaluate the deterministic
answer and its sources before considering optional narration.

Pass criteria:

1. The answer is based on the expected source or explicitly says no relevant
   record was found.
2. Source labels remain visible and in deterministic order.
3. The result does not offer legal, medical, or financial advice.
4. A missing answer becomes a product finding, not a reason to invent data.

## Optional narration: only after offline validation

If a future test uses an OpenAI API key, choose one non-sensitive question.
Tick the per-request consent control and confirm that:

- deterministic answer and sources appear first;
- the narration is visibly marked as non-authoritative;
- the agent-flow status is recorded;
- audit detail contains only workflow state and source counts, not the
  question, excerpts, or narration output.

## Owner and heir controls

Do not test a real heir with real credentials in the first batch. First verify
that owner lock/unlock and integrity checks work. Formal heir registration,
keys, and passphrase recovery remain deliberate separate steps in the existing
CLI path.

## What to report back

For every surprising result, record a short row in the oracle:

```text
ST-001 | source: old-bank-note.md | expected: accounts | observed: personal |
query: "Which bank account is current?" | source was stale | severity: medium
```

Do not paste raw personal content into an issue, commit, chat, or screenshot.
