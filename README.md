# Satchel

Satchel is a small Bitcoin wallet that runs as a Cloudflare Worker. AI agents call it over the Model Context Protocol (MCP) to read a balance and to build, sign, and broadcast transactions. The seed stays in a Worker secret. The worker is the only place that can sign.

This repository is public. Do not commit a seed, an extended private key, a bearer token, or an API key.

## Quickstart

You need a Cloudflare account, `wrangler` 4, Rust stable, the `wasm32-unknown-unknown` target, `clang`, and `llvm-ar`. The `secp256k1` crate compiles C. `gcc` cannot target `wasm32-unknown-unknown`, so the build uses `clang`. `.cargo/config.toml` points the wasm build at `clang` and `llvm-ar`.

```bash
git clone https://github.com/CharmsDev/btc-wallet-worker
cd btc-wallet-worker
rustup target add wasm32-unknown-unknown
cargo install worker-build --version 0.8.7
```

1. Edit `wrangler.toml`. Replace `wallet.example.com` with your hostname. Leave `workers_dev` and `preview_urls` set to `false`, so the custom domain is the only route.
2. Create a 12-word or 24-word BIP39 mnemonic that does not already hold funds you care about. Put it only in a Worker secret.

```bash
npx wrangler secret put BTC_WALLET_SEED
npx wrangler secret put MCP_CLIENT_TOKENS
```

`MCP_CLIENT_TOKENS` is one JSON object. Each name is a client you can revoke on its own. Each token is at least 16 characters.

```json
{"cursor":"<long random token>","claude":"<another long random token>"}
```

3. Deploy.

```bash
npx wrangler deploy
```

4. Put the hostname behind Cloudflare Access with a service-token-only policy. Set `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` in `wrangler.toml`, then deploy again. `scripts/setup-access.sh` creates the Access application and one service token when `CF_API_TOKEN`, `CF_ACCOUNT_ID`, and `APP_DOMAIN` are set. It prints the AUD tag and the service token once.

There is no Deploy to Cloudflare button. That button builds in an environment without the Rust and clang toolchain this worker needs.

## Configure

Vars live in `wrangler.toml`. Secrets are set with `wrangler secret put` and are not in the repo.

| Name | Kind | Default | Role |
| --- | --- | --- | --- |
| `NETWORK` | var | `mainnet` | `mainnet`, `testnet`, `signet`, or `regtest` |
| `SCRIPT` | var | `bip84` | `bip84` (native segwit) or `bip86` (taproot) |
| `ACCOUNT` | var | `0` | BIP44 account index |
| `GAP_LIMIT` | var | `20` | Unused-address gap counted after issued receive indexes |
| `MAX_SCAN_INDEX` | var | `200` | Highest index discovery will probe. `address` will not issue an index whose trailing gap would pass it |
| `MAX_CHAIN_CALLS` | var | `80` | Esplora calls allowed in one tool call |
| `FEE_TARGET_BLOCKS` | var | `3` | Confirmation target when `feerate` is omitted |
| `MAX_TX_INPUT_SATS` | var | `100000` | Max sum of all input values in one transaction |
| `AUTO_LOCK_SATS` | var | `330` | Wallet coins at or under this value are locked until `unlock`. `0` locks no coin with a positive value. A value that is not a whole number is a config error |
| `IDEMPOTENCY_TTL_HOURS` | var | `168` | Hours a `request_id` keeps its signed transaction. Must be 24 to 168. A value outside that range is a config error |
| `ESPLORA_URLS` | var | empty | Comma-separated Esplora bases. Empty uses the defaults below |
| `EXPECTED_FINGERPRINT` | var | empty | 8 hex characters. When set, signing is refused if the seed does not match |
| `ACCESS_TEAM_DOMAIN` | var | empty | Team name or `team.cloudflareaccess.com`. Set with `ACCESS_AUD` |
| `ACCESS_AUD` | var | empty | Access application AUD tag |
| `BTC_WALLET_SEED` | secret | | BIP39 mnemonic, no passphrase |
| `MCP_CLIENT_TOKENS` | secret | | JSON map of client name to bearer token |
| `BLOCKSTREAM_API_KEY` | secret | optional | `client_id:client_secret` for Blockstream Explorer Enterprise |

Account paths:

- BIP84 mainnet is `m/84'/0'/0'`. Testnet, signet, and regtest use coin type `1`.
- BIP86 mainnet is `m/86'/0'/0'`.

External chain is `/0/*`. Change is `/1/*`. There is no BIP39 passphrase.

`NETWORK=regtest` has no public default. Set `ESPLORA_URLS` to your own Esplora.

When `ESPLORA_URLS` is empty and `BLOCKSTREAM_API_KEY` is set, mainnet tries `https://enterprise.blockstream.info/api` first, then `https://blockstream.info/api`, then `https://mempool.space/api`. Testnet uses the `/testnet/api` forms, including `https://enterprise.blockstream.info/testnet/api` when a key is set. Signet uses `https://blockstream.info/signet/api` and `https://mempool.space/signet/api`. A custom list replaces those defaults. OAuth is attached only to hosts under `enterprise.blockstream.info`.

The key is sent to `https://login.blockstream.com/realms/blockstream-public/protocol/openid-connect/token` with `grant_type=client_credentials` and `scope=openid`. The access token is cached until shortly before `expires_in` and is not logged or returned.

Fee estimates are rounded up to the next whole sat/vB.

## MCP clients

The endpoint is `POST /mcp`. The body is one JSON-RPC 2.0 message. The server is stateless and returns `application/json`. Supported protocol versions are `2025-06-18`, `2025-03-26`, and `2024-11-05`.

Tools: `balance`, `address`, `history`, `utxos`, `lock`, `unlock`, `fee_estimates`, `descriptor`, `send`, `sign_psbt`, `sign_tx`, `spend_log`.

`send`, `sign_psbt`, and `sign_tx` default to `broadcast: false`. `send` then returns the fee, vsize, outputs, input sum, and an unsigned PSBT. It signs and broadcasts only when `broadcast` is `true`. `sign_psbt` signs only when every input has a known value and the input sum is within `MAX_TX_INPUT_SATS`. `broadcast: true` on `sign_psbt` also submits the transaction.

`sign_tx` takes a consensus-hex transaction in `tx_hex` and returns the signed hex in `tx_hex`. It signs only the inputs that spend this wallet's outputs. Every other input and every output stay byte for byte as sent, including an `OP_RETURN`. It fetches the transaction behind each input from Esplora to learn the value that input spends, and refuses a fetched transaction that does not hash to its txid. A prevout it cannot fetch is an error, and nothing is signed. `broadcast: true` on `sign_tx` submits the transaction only when every input is signed.

Every call that signs needs a `request_id`. That is `send` with `broadcast: true`, and every `sign_psbt` and `sign_tx` call. A `request_id` is 1 to 80 letters, digits, or `.` `_` `:` `-`. Use a new one for each payment. A dry-run `send` checks the format of a `request_id` and then ignores it.

To retry after an error or a lost reply, send the same arguments with the same `request_id`. Satchel returns the stored result. If no broadcast of the stored transaction was confirmed, it broadcasts that same transaction again. A retry does not select coins or sign a second time. The arguments that count:

- `send` counts `to`, `sats`, and `feerate`, plus the set of `inputs` when present. The order of `inputs` does not matter. A `send` without `inputs` is the same request it was before coin control.
- `sign_psbt` counts the unsigned transaction and `broadcast`, plus `allow_locked` when it is `true`.
- `sign_tx` counts the exact transaction bytes, `broadcast`, and `allow_locked`. A changed witness is a new request.

- The same `request_id` with different arguments is an error.
- A retry that arrives while the first call is still signing gets an in-progress error. Wait and retry with the same arguments.
- Keys belong to one client name. Two clients can use the same `request_id` without a conflict.
- A key expires after `IDEMPOTENCY_TTL_HOURS`. After that, the same `request_id` starts a new payment.
- The store holds at most 512 live keys. When it is full, it refuses a new key until old keys expire. It never drops a stored transaction to make room.

Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "satchel": {
      "url": "https://wallet.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <client token>",
        "CF-Access-Client-Id": "<access client id>",
        "CF-Access-Client-Secret": "<access client secret>"
      }
    }
  }
}
```

Claude Desktop or Claude Code:

```json
{
  "mcpServers": {
    "satchel": {
      "type": "streamable-http",
      "url": "https://wallet.example.com/mcp",
      "headers": {
        "Authorization": "Bearer <client token>",
        "CF-Access-Client-Id": "<access client id>",
        "CF-Access-Client-Secret": "<access client secret>"
      }
    }
  }
}
```

Any other Streamable HTTP client uses the same URL and headers. Missing or wrong auth returns HTTP 401. `GET /` returns only the service name. `GET /mcp` returns 405.

## Coin control

`utxos` lists each coin with its address, `script_pubkey` in hex, `script_type` (`p2wpkh` or `p2tr`), and `path` (`0/<index>` on the receive chain, `1/<index>` on change). A locked coin has `locked: true` and a `lock_reason` of `manual` or `auto-small`. An unlocked coin has `locked: false` and no `lock_reason`.

- A wallet coin at or under `AUTO_LOCK_SATS` (default 330) is locked until you `unlock` it. Charm-bearing outputs are often this small, and a charm spell itself sits in an `OP_RETURN` of a transaction you build and pass to `sign_tx`. Automatic selection skips the small output so a normal payment does not spend it. `0` locks no coin with a positive value. The threshold is read on every call, so a new value applies to every coin at once.
- `lock` and `unlock` take `outpoints` as `txid:vout` strings and an optional `note` of up to 200 characters. Calling either twice is the same as calling it once. The last call for an outpoint wins. An outpoint does not need to be a wallet coin. The lock book holds at most 2048 outpoints. A call that would pass that adds none of its outpoints, and rewriting an outpoint already in the book still works.
- The `lock` and `unlock` reply shows only what was stored. Auto-lock depends on a coin's value, which those tools do not look up. `utxos` shows it.
- `send` without `inputs` skips locked coins. If every coin is locked, it says so. The lock book is read again after the coins and the fee are fetched, and immediately before the signature. A `lock` that succeeds during that fetch stops an automatic payment from signing the newly locked coin. With `inputs`, only the listed coins are considered, and they may be locked. Listing a coin is consent to spend it, including a lock saved while the payment is being built. Selection may still leave a listed coin unspent. A listed outpoint that is not a current wallet coin is an error. To spend an exact set, build the transaction yourself and call `sign_tx`.
- `sign_psbt` and `sign_tx` refuse to spend a locked outpoint unless `allow_locked` is `true`. The error names every locked input. Auto-lock applies to this wallet's outputs only. A manual lock applies to any outpoint in the book, including one this wallet does not own. A foreign output under the threshold is not auto-locked.

## Access

Use two checks.

1. Cloudflare Access on the hostname, with a policy whose action is Service Auth and whose include rule is a service token (or any valid service token). Agents send `CF-Access-Client-Id` and `CF-Access-Client-Secret`. Access then adds `Cf-Access-Jwt-Assertion`.
2. The worker checks `Authorization: Bearer <token>` against `MCP_CLIENT_TOKENS` with a constant-time compare of SHA-256 hashes. When `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are both set, the worker also verifies the Access JWT against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` and the AUD tag. If only one of those vars is set, every request fails closed.

To revoke one agent, remove its name from `MCP_CLIENT_TOKENS` and run `wrangler secret put MCP_CLIENT_TOKENS` again. To revoke Access, delete that service token in the Zero Trust dashboard. Rotate by generating a new token, updating the clients that use it, then deleting the old one.

## Limits

The worker is a hot wallet. A stolen bearer token, a stolen Access service token, or a bug in an agent can spend the coins this wallet can sign. Keep the balance small.

The only spend limit is `MAX_TX_INPUT_SATS` (default 100,000). The sum of every input in the transaction must be within that number, for `send`, `sign_psbt`, and `sign_tx`. Inputs this wallet does not own count toward the sum. `send` skips a coin that would push the selection over that cap and tries a smaller set, so a large coin does not block a payment a smaller coin can fund. `sign_psbt` refuses a PSBT when any input has no `witness_utxo` and no `non_witness_utxo`. `sign_tx` refuses a transaction when any prevout cannot be fetched. The check runs before a signature is created. There is no rolling daily cap, no feerate cap, and no separate fee cap. A fee cannot exceed the inputs, so the input cap is also the most one transaction can lose.

Locks guard coins against an accidental spend. They are not a spend limit. A caller can pass `allow_locked: true` or list a locked coin in `send` `inputs`. The lock check runs after the input cap and before a signature is created.

`sign_psbt` allows only `SIGHASH_ALL` for segwit and `SIGHASH_DEFAULT` or `SIGHASH_ALL` for taproot. `sign_tx` writes `SIGHASH_ALL` on segwit inputs and `SIGHASH_DEFAULT` on taproot inputs. Addresses that are not for `NETWORK` are rejected.

The Durable Object stores the signed transaction for each `request_id`, so a retry can return it or broadcast it again. It does not approve or refuse an amount. It also stores the lock book under one key. A `lock` or `unlock` loads, edits, and stores that book in one transaction, so two concurrent edits cannot drop each other's marks.

The spend log is an append-only note of signed transactions: txid, input sum, destination, fee, time, client name, `request_id`, and kind. It does not store the seed, private keys, bearer tokens, or the Blockstream access token. Rows older than 30 days are dropped, and at most 500 rows are kept. A destination longer than 240 characters is stored shortened. If the note would exceed 1 MiB of JSON, the oldest rows are dropped so the write stays under the Durable Object's 2 MB key-and-value cap. That bound is not a spend limit. The log does not block a second transaction. The row is written in the same Durable Object transaction that stores the signed transaction for the `request_id`, so a retry with the same key does not add a second row. If that transaction fails, nothing is broadcast.

Discovery probes every issued receive index before it counts the unused gap, so a deposit to an address from `address` stays visible when earlier indexes are unused. It also probes the gap past the last used index. Raise `MAX_CHAIN_CALLS` if a busy wallet hits the per-call budget. Workers still have a platform subrequest limit. 80 calls fits a paid Worker with room for the Access JWKS and token requests.

## Local development

```bash
cp .dev.vars.example .dev.vars
# edit .dev.vars with a throwaway mnemonic and a long local token
npx wrangler dev
```

Leave `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` empty locally. Point `NETWORK` at `signet` or `testnet` in `wrangler.toml` before you try a broadcast. `regtest` needs `ESPLORA_URLS`.

```bash
curl -s http://127.0.0.1:8787/mcp \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-with-a-long-random-token' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

`.dev.vars` is gitignored.

## Tests

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown -- -D warnings
cargo test
worker-build --release
```

`cargo test` covers the BIP84 and BIP86 vectors for the mnemonic `abandon abandon ... about` with an empty passphrase, address network checks, cap accounting, fee checks, a PSBT sign round trip, lock verdicts and refusals, raw transaction signing for P2WPKH and P2TR, pinned idempotency hashes, bearer comparison, Access JWT verification, and MCP JSON-RPC. GitHub Actions runs the same checks and the wasm build. This environment cannot deploy the worker.
