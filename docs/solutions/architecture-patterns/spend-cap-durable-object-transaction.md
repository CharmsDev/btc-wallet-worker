---
title: Spend caps must use one Durable Object storage transaction
date: 2026-10-08
category: architecture-patterns
module: spend-guard
problem_type: architecture_pattern
component: payments
severity: high
applies_when:
  - A Worker enforces a shared spending limit across concurrent requests
  - The limit is stored in a workers-rs Durable Object
tags:
  - durable-objects
  - workers-rs
  - caps
---

# Spend caps must use one Durable Object storage transaction

## Context

Satchel's per-transaction and rolling 24 hour caps have to hold when two agents call `send` at the same time. The numbers live in the `SpendGuard` Durable Object.

## Guidance

Read the spend state, run `guard::apply`, and write the new state inside `Storage::transaction`. Do not `get` and later `put` as two calls on `Storage`.

`worker` 0.8.7 documents that each `Storage` method is its own transaction. A Durable Object can run another request while the first is waiting on I/O. Two requests can both read the same window, both decide the cap allows the spend, and both write.

```rust
self.state.storage().transaction(move |tx| async move {
    let state = load_or_default(&tx, "spend").await?;
    let (state, result) = crate::guard::apply(state, command, now, &policy);
    tx.put("spend", state).await?;
    *slot_write.borrow_mut() = Some(result);
    Ok(())
}).await?;
```

`guard::apply` is a pure function. The tests cover preview, reserve, commit, abort, release, and the 24 hour window without the Workers runtime. The object only persists that result.

The scan cache uses the same shape, and the merge is a union, so a lost update cannot drop an address that either caller observed.

## Why This Matters

A check that is not atomic lets two spends through that together exceed the cap. The cap is the server-side limit on this hot wallet.

## When to Apply

- The value is a shared counter, budget, or cursor that concurrent requests must not double-spend.
- The update is a read, a decision, and a write, and any step awaits.

## Examples

`SpendGuard::apply_spend` in `src/runtime.rs` is the cap path. `SpendGuard::merge` is the scan path. OAuth token cache is last-write-wins and is not a cap.

## Related

- The cap rules themselves are in `src/guard.rs` and do not know about Durable Objects.
