# Continuum public evaluation build

Static, zero-backend evaluator for judges. It demonstrates deterministic,
source-backed outcomes using curated synthetic fixtures. It intentionally does
**not** publish a source corpus, vault,
credentials, recovery shares, API keys, or an external AI integration.

## Deploy to Vercel

Import this directory as a Vercel project, or deploy it from the command line:

```bash
npx vercel --prod
```

No framework, build step, environment variable, or API key is required. The
project root must be this `web-demo` directory.

## What judges can test

- Needle retrieval with a redacted credential reference.
- Multi-source and ambiguous evidence.
- Honest no-evidence response for blood type.
- Prompt-injection/access request refusal.
- Owner, 3-of-5 recovery, and read-only heir boundaries.

For the real encrypted local application, see the linked Continuum repository.
