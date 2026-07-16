# Continuum — Codex Project Notes

## Scope

Continuum is the hackathon evolution of the Digital Legacy prototype. The
prototype is the current technical baseline; product naming and code-module
renaming will happen in later migration steps.

## Documentation rules

- Write project documentation in English.
- Use Markdown and fenced code blocks for commands and source examples.
- Use Codex terminology and references. Do not add assistant-specific branch
  names, session labels, or attribution metadata.
- Keep security findings and adversarial audit reports outside the migrated
  product documentation unless explicitly requested.
- Preserve the distinction between implemented guarantees, mitigations, and
  future work.

## Deterministic-core contract

- The existing `legacy/` package is the deterministic core until a deliberate,
  separately tested package migration is approved. Do not rename it as part of
  product work.
- Classification, ranking, access control, integrity verification, and any
  decision about which records are selected stay offline and deterministic.
- A model may only narrate a complete, core-selected result. It must not
  invent, omit, reorder, or select records; it must not give legal, financial,
  or medical advice.
- If the core returns no relevant record, the user-facing response must say so
  explicitly. Do not use a model to fill the gap.

## Agent and privacy contract

- Any OpenAI agent is a single-purpose narrator over the core result. Do not
  give it write, unlock, ranking, classification, or policy tools.
- Plaintext may leave the device only after a clear, per-request opt-in. Send
  only the selected excerpts needed for that narration.
- Agent calls must be stateless (`store=False`) and disable SDK tracing unless
  a future, explicitly reviewed privacy design says otherwise.
- Never simulate the deceased person, including voice, face, personality, or
  first-person impersonation.

## Change discipline

- Make small, verifiable changes. Add or update tests and run the relevant
  tests after each code change.
- Before changing OpenAI runtime code, verify current model names and API/SDK
  calls against official OpenAI documentation.

## Source of truth

The initial documentation migration is based on `/home/labestiadevigia/digital-legacy`.
The excluded source material is the set of adversarial security audit reports
and the dated code-review report in the source repository.
