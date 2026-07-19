# Retrieval bug: three compounding causes, found during real-corpus testing

Date: 2026-07-19
File: `legacy/memory/field.py`
Status: fixed, verified, 471/471 existing tests still pass

## What we observed

While rehearsing a demo with a mixed-format corpus (17 files: `.md`, `.txt`,
`.csv`, `.json`, `.xlsx`), one document contained a household-credentials
table under a memorable codeword ("sillonrojo") that appears nowhere else in
the corpus. Two natural-language queries that should have surfaced it did
not:

- `"where is sillonrojo"` — the document ranked 4th out of 8 results.
- `"what is the password for the NAS admin panel"` — the document did not
  appear in the top 8 at all.

The module's own docstring and README both describe this scorer as
"deterministic TF-IDF cosine." A document containing the exact literal
query term should not be outranked by unrelated documents.

## What we found

Three separate, compounding bugs, uncovered one at a time — fixing the
first exposed the second, fixing the second exposed the third.

### 1. `_tfidf_vector` computed TF, never IDF

```python
# before
def _tfidf_vector(tokens, vocab):
    count = Counter(tokens)
    total = max(len(tokens), 1)
    vec = [count.get(w, 0) / total for w in vocab]   # term frequency only
    ...
```

There was no inverse-document-frequency term anywhere. Every word
contributed to similarity in proportion to how often it appeared in a given
document, with no discount for how common that word is across the whole
corpus. Generic query words ("what", "is", "the", "password", "for") counted
exactly as much as the one word that actually distinguishes the right
document.

**Fix:** added `_idf_weights()` (smoothed: `log((N+1)/(df+1)) + 1`, always
positive so a term in every document still contributes) and multiplied it
into the term-frequency vector before normalizing.

### 2. The vocabulary cap kept the wrong words

```python
# before
vocab = sorted(t for t, _ in all_tokens.most_common(512))
```

The memory field caps its vocabulary at 512 terms for memory/compute
reasons. When trimming, it kept the *most frequent* terms and discarded the
rest. That is backwards for a search index: the most frequent words across a
corpus (function words, boilerplate) carry the least discriminative signal,
while a name, codeword, or identifier that appears in exactly one document
is the single most useful thing to keep. With 17 documents already exceeding
512 unique tokens (JSON keys, CSV headers, boilerplate), "sillonrojo" — the
one word that made the demo's needle-in-haystack query work — was pruned out
of the vocabulary entirely. It could not affect any score, because it was not
in the coordinate space at all, independent of bug #1's fix.

**Fix:** rank candidate terms by ascending document frequency (rarest first,
alphabetical tie-break) before applying the cap, both when the vocabulary is
rebuilt from scratch (`_load_vocab`) and when it grows incrementally on
every `store()`.

### 3. `recall()` trusted a stale stored embedding whenever its length matched

```python
# before
if q_vec and emb and len(q_vec) == len(emb):
    cos = _cosine(q_vec, emb)          # trust the stored vector
elif q_vec:
    fresh_emb = _tfidf_vector(_tokenize(content), self._vocab)
    cos = _cosine(q_vec, fresh_emb)    # only recomputed on shape mismatch
```

Each memory's embedding is precomputed once, at `store()` time, and cached
in `embedding_json`. Before IDF existed, "same vocabulary length" was a
reasonable proxy for "this stored vector is still valid," because plain term
frequency never depends on anything outside the document itself. IDF breaks
that assumption: document-frequency counts for the whole corpus keep
shifting as new memories are stored, even after the vocabulary's *size* stops
growing (once it hits the 512 cap, membership can still change while length
stays fixed at 512). A stored vector built against yesterday's document
frequencies can have the *same length* as today's query vector while being
numerically wrong — and the shape check had no way to detect that. This is
what made bug #1's fix alone insufficient: the fresh IDF math was correct,
but `recall()` kept reading a stale cached score instead of using it, for
any document whose stored embedding happened to already be 512-dimensional.

**Fix:** `recall()` now always recomputes each memory's embedding from its
(already-decrypted) content against the *current* vocabulary and IDF weights,
instead of conditionally trusting the cached one. Content is already
decrypted for every row in the recall loop regardless, so this adds no new
decryption cost — only the token/vector computation the fallback path was
already doing.

## Why this mattered beyond one demo query

All three bugs get *worse*, not better, as the corpus grows — which is
exactly the direction the real workload moves (17 synthetic files today, on
the way to roughly 300 real documents). A bigger corpus means:

- more terms competing for the 512-slot vocabulary cap, so bug #2 discards
  more distinctive words, not fewer;
- more documents contributing to document frequency, so bug #3's staleness
  window (vocabulary length pinned at the cap) opens sooner, not later;
- more overlap in common words across documents, so bug #1's missing IDF
  dilutes ranking more, not less.

A fix that only worked on a small corpus would have been the wrong fix.

## Verification

Reproduced against a fresh vault ingesting the same 17-file corpus after each
incremental fix, using the CLI (`legacy query`), not a synthetic unit test —
the same code path the product actually uses:

| Query | Before | After |
|---|---|---|
| `"where is sillonrojo"` | ranked 4th of 8 | **ranked 1st of 8** |
| `"what is the password for the NAS admin panel"` | not in top 8 | **ranked 1st of 8** |

Full existing test suite: 471/471 passed, both before and after — no
regression, and no existing test encoded the buggy behavior as expected.
