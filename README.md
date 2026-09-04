# ArbiFlow — real-deposit backend foundation

This version adds authentication, PostgreSQL, a double-entry-style immutable ledger, deposit records, idempotent signed deposit webhooks, and balance endpoints.

## Important
It is **not safe to accept customer funds until you configure a real custody/payment provider** and complete your legal/compliance/security review. The server intentionally does not generate or store seed phrases/private keys.

## Database
Run `schema.sql` against your PostgreSQL database.

## Environment
Copy `.env.example` to `.env` locally. On Render, add the same variables under Environment.

## Deposit provider integration
Provision user deposit addresses with your chosen custody/payment provider. Store the public deposit address in `wallets`:

INSERT INTO wallets(user_id,asset,network,deposit_address) VALUES (...);

Configure the provider to POST signed events to:
POST /api/webhooks/deposits
and signed confirmation updates to:
POST /api/webhooks/deposits/confirm

Signature:
HMAC-SHA256(raw JSON body, DEPOSIT_WEBHOOK_SECRET)
header: x-deposit-signature

Only a `confirmed` event creates a ledger credit. Duplicate provider events are rejected by `provider_event_id`.

Never commit private keys, seed phrases, exchange secrets, or webhook secrets to GitHub.
