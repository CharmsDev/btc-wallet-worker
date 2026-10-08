---
title: The input cap is checked before signing and does not use the Durable Object
date: 2026-10-08
category: architecture-patterns
module: spend-guard
problem_type: architecture_pattern
component: payments
severity: medium
applies_when:
  - A transaction is about to be signed by Satchel
tags:
  - input-cap
  - sighash
  - durable-objects
---

# The input cap is checked before signing and does not use the Durable Object

## Context

Satchel used to reserve outflow, fee, and a rolling 24 hour total inside `SpendGuard` before it signed. That reservation existed so two overlapping requests could not both pass the daily cap, and so an unclear broadcast would not free the reservation.

## Guidance

`MAX_TX_INPUT_SATS` is the only spend limit. `transaction_input_sats` sums every input. `sign_psbt` calls `enforce_input_cap` before `require_committing_sighash` and before `Psbt::sign`. An input with neither `witness_utxo` nor `non_witness_utxo` is refused.

The Durable Object still stores the address scan and an append-only spend log. It does not approve or release a spend. Sighash stays restricted to `SIGHASH_ALL` and taproot `SIGHASH_DEFAULT`, because a weaker sighash would let the caller change the transaction after the input sum was checked.

## Why This Matters

A daily cap and a fee cap need shared mutable state. An input-sum cap does not. Putting it back into the Durable Object would reintroduce the reservation machinery this change removed.

## When to Apply

- You are about to add a second spending limit that concurrent requests could both pass.
- You are about to sign a PSBT whose sighash does not commit to every input and output.

## Examples

`sign_psbt` in `src/tx.rs` is the gate. `SpendGuard::append_spend` in `src/runtime.rs` only records a transaction that was already signed.

## Related

- Replacing this with a rolling cap would need one storage transaction around the check and the write. That pattern was the previous contents of this note.
