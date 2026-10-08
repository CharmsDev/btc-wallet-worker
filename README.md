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
| `GAP_LIMIT` | var | `20` | Unused-address gap on both chains |
| `MAX_SCAN_INDEX` | var | `200` | Highest index the scan will probe |
| `MAX_CHAIN_CALLS` | var | `80` | Esplora calls allowed in one tool call |
| `FEE_TARGET_BLOCKS` | var | `3` | Confirmation target when `feerate` is omitted |
| `PER_TX_CAP_SATS` | var | `100000` | Max sats leaving the wallet in one spend, including fee |
| `ROLLING_24H_CAP_SATS` | var | `250000` | Max sats leaving the wallet in 24 hours |
| `MAX_FEERATE_SAT_VB` | var | `200` | Max fee rate in sat/vB |
| `MAX_FEE_SATS` | var | `20000` | Max absolute fee |
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

Tools: `balance`, `address`, `history`, `utxos`, `fee_estimates`, `descriptor`, `send`, `sign_psbt`, `spend_log`.

`send` and `sign_psbt` default to `broadcast: false`. `send` then returns the fee, vsize, outputs, cap status, and an unsigned PSBT. It signs and broadcasts only when `broadcast` is `true`. `sign_psbt` returns a signed PSBT only after the outflow is counted against the cap, because a signed PSBT can be broadcast elsewhere. `broadcast: true` on `sign_psbt` also submits the transaction.

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

## Access

Use two checks.

1. Cloudflare Access on the hostname, with a policy whose action is Service Auth and whose include rule is a service token (or any valid service token). Agents send `CF-Access-Client-Id` and `CF-Access-Client-Secret`. Access then adds `Cf-Access-Jwt-Assertion`.
2. The worker checks `Authorization: Bearer <token>` against `MCP_CLIENT_TOKENS` with a constant-time compare of SHA-256 hashes. When `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are both set, the worker also verifies the Access JWT against `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` and the AUD tag. If only one of those vars is set, every request fails closed.

To revoke one agent, remove its name from `MCP_CLIENT_TOKENS` and run `wrangler secret put MCP_CLIENT_TOKENS` again. To revoke Access, delete that service token in the Zero Trust dashboard. Rotate by generating a new token, updating the clients that use it, then deleting the old one.

## Limits

The worker is a hot wallet. A stolen bearer token, a stolen Access service token, or a bug in an agent can spend what the caps allow. Keep the balance small. The defaults are 100,000 sats per transaction and 250,000 sats per rolling 24 hours, with a fee cap of 20,000 sats and 200 sat/vB.

Caps are applied inside one Durable Object, `SpendGuard`, so two overlapping requests cannot both pass a check that only one of them should pass. A reservation counts against the cap immediately. It expires after two minutes if the worker crashes before commit. Broadcasting a transaction that the network rejects releases that reservation. Returning a signed PSBT does not release it.

`send` counts the payment plus the fee. `sign_psbt` counts the net sats leaving the wallet (inputs it owns, minus outputs that pay it). It signs only `SIGHASH_ALL` for segwit and `SIGHASH_DEFAULT` or `SIGHASH_ALL` for taproot. Addresses that are not for `NETWORK` are rejected. A broadcast that fails in transit keeps the reservation. The reservation is released only when a backend rejects the transaction and no backend shows that txid.

The spend log stores txid, outflow, destination, fee, time, client name, and kind. It does not store the seed, private keys, bearer tokens, or the Blockstream access token. Rows older than 30 days are dropped.

The scan remembers which addresses have been used. Later calls only probe the gap past the last used index, plus holes that were never used. Raise `MAX_CHAIN_CALLS` if a busy wallet hits the per-call budget. Workers still have a platform subrequest limit. 80 calls fits a paid Worker with room for the Access JWKS and token requests.

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

`cargo test` covers the BIP84 and BIP86 vectors for the mnemonic `abandon abandon ... about` with an empty passphrase, address network checks, cap accounting, fee checks, a PSBT sign round trip, bearer comparison, Access JWT verification, and MCP JSON-RPC. GitHub Actions runs the same checks and the wasm build. This environment cannot deploy the worker.
