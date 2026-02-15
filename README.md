# Contract Risk Scanner (MVP)

Upload a contract PDF, extract renewal/end date + notice period evidence, compute a suggested cancel-by date, and (optionally) email the result.

## Safety / guardrails
- **Human-in-the-loop:** you must review evidence before sending.
- **Rolling monthly:** the app does not guess a cancel-by date without a next renewal/billing date.
- **Tenancy detection:** tenancy-style documents are flagged and computation/AI is skipped.
- **AI is fallback-only:** short, redacted snippets only (never full contract), strict JSON validation.

## Requirements
- Node.js 20+ recommended

## Setup
```bash
cd contract_risk_mvp
npm ci
cp .env.example .env
# set OPENAI_API_KEY if you enable AI
```

## Run
```bash
node app.js
# then open http://127.0.0.1:3005
```

## Environment
See `.env.example`.

## Notes
- Uploaded PDFs are deleted immediately after extraction.
