---
title: A retry must load the stored transaction before it selects coins
date: 2026-10-09
last_updated: 2026-10-10
category: architecture-patterns
module: idempotency
problem_type: architecture_pattern
component: payments
severity: high
applies_when:
  - A client retries send or sign_psbt after a lost or failed broadcast reply
tags:
  - idempotency
  - request-id
  - coin-selection
---

# A retry must load the stored transaction before it selects coins

## Context

`request_id` pins one signed transaction so a lost broadcast reply can be sent again. The first call claims the key, then builds and signs, then stores the raw transaction, then broadcasts. A later call with the same key must not build again.

## Guidance

`App::effect` sends `Op::Begin` before `sign_send`, `sign_foreign`, or `sign_raw_tx`. Those are the only paths that scan addresses, fetch prevouts, or select coins. When `Begin` returns a stored transaction, `settle` broadcasts that hex or returns the stored result. It does not call `build_payment` or `sign_raw`.

The claim is empty until `Commit`. A second caller that arrives while the claim is live gets `InProgress` and does not sign. After the signed transaction is stored, a retry rebroadcasts those bytes. Esplora answers that the transaction is already in the mempool count as success.

## Why This Matters

`build_payment` returns `not enough funds` when the previous inputs are gone from the Esplora UTXO list. That is the normal state after the first broadcast was accepted and the HTTP reply was lost. If the retry selected coins before it read the stored transaction, the client would see a funding error for a payment that already went out, and a new `request_id` would be free to spend a different set of coins to the same destination.

## When to Apply

- You are about to move coin selection, fee estimation, or PSBT inspection ahead of the idempotency lookup.
- You are about to broadcast a hex that `Decision::Rebroadcast` did not return.

## Examples

A repeated `send` with the same `request_id`, destination, amount, and requested feerate returns the stored txid. The feerate that went into the hash is the client's argument. The estimate filled in when that argument was omitted is not part of the hash, so a later estimate does not mint a second transaction.

`Canon::send` appends the input set only when `inputs` is present. `Canon::sign` appends a byte only when `allow_locked` is true. A retry that omits those arguments still matches a hash stored before the fields existed. A different preimage is `Mismatch`, and `Mismatch` does not rebroadcast the stored transaction. `Canon::sign_tx` is a separate kind. It hashes the raw transaction bytes, so a witness added by another signer is a different request and needs its own `request_id`.

## Related

- The input cap stays in the worker, before `Psbt::sign`. The Durable Object does not approve an amount. See `spend-cap-durable-object-transaction.md`.
