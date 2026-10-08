use crate::auth::{verify_access_jwt, AccessRules, Clients};
use crate::config::{Config, RawConfig};
use crate::esplora::{
    classify_attempt, fold_broadcast, form_encode, parse_address_stats, parse_api_key,
    parse_fee_estimates, parse_history_page, parse_token_response, parse_utxos, pick_feerate,
    AddressStats, AttemptClass, BroadcastVerdict, RawAttempt, Utxo,
};
use crate::guard::{
    attach_log_warning, join_log_warning, merge_scan, take_receive, unlogged_spend_warning,
    GuardOp, GuardReply, OauthCache, SpendKind, SpendRecord,
};
use crate::mcp::{self, Incoming, ToolCall};
use crate::policy::enforce_input_cap;
use crate::scan::{history_indexes, next_probe, ProbeStep, ScanCache};
use crate::tx::{
    annotate_owned_inputs, build_payment, extract_signed, indexes_from_origins, inspect_psbt,
    psbt_from_base64, psbt_to_base64, sign_psbt, transaction_input_sats, Coin, Payment,
};
use crate::wallet::{parse_address, ChainKind, Wallet};
use bitcoin::psbt::Psbt;
use bitcoin::ScriptBuf;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use worker::*;

const TOKEN_URL: &str =
    "https://login.blockstream.com/realms/blockstream-public/protocol/openid-connect/token";

struct JwksCache {
    exp_ms: u64,
    body: String,
}

thread_local! {
    static JWKS: RefCell<Option<JwksCache>> = const { RefCell::new(None) };
}

pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    Router::new()
        .get("/", |_req, _ctx| health())
        .post_async("/mcp", mcp)
        .get_async("/mcp", |_req, _ctx| async move { method_not_allowed() })
        .run(req, env)
        .await
}

fn health() -> Result<Response> {
    json_bytes(200, r#"{"service":"satchel","mcp":"/mcp"}"#)
}

fn method_not_allowed() -> Result<Response> {
    json_bytes(405, r#"{"error":"method not allowed"}"#)
}

async fn mcp(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let config = match load_config(&ctx) {
        Ok(config) => config,
        Err(message) => {
            return json_bytes(500, &serde_json::json!({ "error": message }).to_string());
        }
    };
    let client = match authorize(&req, &ctx, &config).await {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };
    let body = req.text().await?;
    if body.len() > 300_000 {
        return json_value(
            200,
            &mcp::rpc_error(Value::Null, -32600, "request is too large"),
        );
    }
    let protocol = req.headers().get("MCP-Protocol-Version").ok().flatten();
    match mcp::incoming(&body, protocol.as_deref()) {
        Incoming::Notification => Response::empty().map(|response| response.with_status(202)),
        Incoming::Reply { status, body } => json_value(status, &body),
        Incoming::Call { id, call } => {
            let mut app = App {
                ctx: &ctx,
                config: &config,
                client,
                calls: 0,
            };
            match app.dispatch(call).await {
                Ok(value) => json_value(200, &mcp::tool_result(&id, value, false)),
                Err(message) => json_value(
                    200,
                    &mcp::tool_result(&id, json!({ "error": message }), true),
                ),
            }
        }
    }
}

struct App<'a> {
    ctx: &'a RouteContext<()>,
    config: &'a Config,
    client: String,
    calls: u32,
}

impl App<'_> {
    async fn dispatch(&mut self, call: ToolCall) -> Result<Value, String> {
        match call {
            ToolCall::Balance => self.balance().await,
            ToolCall::Address { advance } => self.address(advance).await,
            ToolCall::History { limit } => self.history(limit).await,
            ToolCall::Utxos => self.utxos().await,
            ToolCall::FeeEstimates => self.fee_estimates().await,
            ToolCall::Descriptor => self.descriptor(),
            ToolCall::Send {
                to,
                sats,
                feerate,
                broadcast,
                request_id,
            } => self.send(&to, sats, feerate, broadcast, request_id).await,
            ToolCall::SignPsbt {
                psbt,
                broadcast,
                request_id,
            } => self.sign_psbt(&psbt, broadcast, request_id).await,
            ToolCall::SpendLog { limit } => self.spend_log(limit).await,
        }
    }

    fn wallet(&self) -> Result<Wallet, String> {
        let mut seed = secret(self.ctx, "BTC_WALLET_SEED")
            .ok_or_else(|| "BTC_WALLET_SEED is missing".to_string())?;
        if seed.trim().is_empty() {
            seed.clear();
            return Err("BTC_WALLET_SEED is missing".into());
        }
        Wallet::open(
            seed,
            self.config.network,
            self.config.script,
            self.config.account,
        )
    }

    fn descriptor(&self) -> Result<Value, String> {
        let wallet = self.wallet()?;
        Ok(json!({
            "fingerprint": wallet.fingerprint().to_string(),
            "fingerprint_ok": wallet.fingerprint_ok(self.config.expected_fingerprint).is_ok(),
            "network": wallet.network().to_string(),
            "script": wallet.script().to_string(),
            "account_path": wallet.account_path(),
            "external": wallet.descriptor(ChainKind::External),
            "change": wallet.descriptor(ChainKind::Change),
        }))
    }

    async fn balance(&mut self) -> Result<Value, String> {
        let wallet = self.wallet()?;
        let (cache, mut stats_ext, mut stats_chg) = self.discover(&wallet).await?;
        let mut confirmed = 0i64;
        let mut unconfirmed = 0i64;
        for index in &cache.used_external {
            let stats = self
                .stats(&wallet, ChainKind::External, *index, &mut stats_ext)
                .await?;
            confirmed += stats.confirmed_sats;
            unconfirmed += stats.unconfirmed_sats;
        }
        for index in &cache.used_change {
            let stats = self
                .stats(&wallet, ChainKind::Change, *index, &mut stats_chg)
                .await?;
            confirmed += stats.confirmed_sats;
            unconfirmed += stats.unconfirmed_sats;
        }
        Ok(json!({
            "confirmed_sats": confirmed,
            "unconfirmed_sats": unconfirmed,
            "network": self.config.network.to_string(),
            "script": self.config.script.to_string(),
            "fingerprint": wallet.fingerprint().to_string(),
            "fingerprint_ok": wallet.fingerprint_ok(self.config.expected_fingerprint).is_ok(),
        }))
    }

    async fn address(&mut self, advance: bool) -> Result<Value, String> {
        let wallet = self.wallet()?;
        let _ = self.discover(&wallet).await?;
        let reply = guard_call(
            self.ctx,
            &GuardOp::AllocateReceive {
                advance,
                max_index: self.config.max_scan_index,
                gap: self.config.gap_limit,
            },
        )
        .await?;
        let index = match reply {
            GuardReply::ReceiveIndex { index } => index,
            GuardReply::Error { message } => return Err(message),
            _ => return Err("spend guard did not allocate an address".into()),
        };
        let derived = wallet.derive(ChainKind::External, index)?;
        Ok(json!({
            "address": derived.address.to_string(),
            "index": index,
            "chain": "external",
        }))
    }

    async fn utxos(&mut self) -> Result<Value, String> {
        let wallet = self.wallet()?;
        let coins = self.collect_utxos(&wallet).await?;
        let rows: Vec<Value> = coins
            .iter()
            .map(|coin| {
                json!({
                    "txid": coin.txid.to_string(),
                    "vout": coin.vout,
                    "value_sats": coin.value,
                    "confirmed": coin.confirmed,
                })
            })
            .collect();
        Ok(json!({ "utxos": rows }))
    }

    async fn history(&mut self, limit: u32) -> Result<Value, String> {
        let wallet = self.wallet()?;
        let (cache, _, _) = self.discover(&wallet).await?;
        let targets = history_indexes(&cache.used_external, &cache.used_change);
        let mut ours = Vec::with_capacity(targets.len());
        for (chain, index) in &targets {
            let kind = match chain {
                0 => ChainKind::External,
                1 => ChainKind::Change,
                _ => return Err("history index chain is invalid".into()),
            };
            ours.push(wallet.derive(kind, *index)?.address.to_string());
        }
        let mut seen = BTreeSet::new();
        let mut rows = Vec::new();
        for address in &ours {
            let mut path = format!("/address/{address}/txs");
            loop {
                let body = self.esplora_get(&path).await?;
                let page = parse_history_page(&body, &ours)?;
                for tx in page.txs {
                    if seen.insert(tx.txid.clone()) {
                        rows.push(tx);
                    }
                }
                let Some(cursor) = page.next_confirmed else {
                    break;
                };
                if rows.len() >= limit as usize {
                    break;
                }
                path = format!("/address/{address}/txs/chain/{cursor}");
            }
        }
        rows.sort_by(|left, right| match (left.confirmed, right.confirmed) {
            (false, true) => std::cmp::Ordering::Less,
            (true, false) => std::cmp::Ordering::Greater,
            _ => right
                .block_height
                .unwrap_or(0)
                .cmp(&left.block_height.unwrap_or(0)),
        });
        rows.truncate(limit as usize);
        let transactions: Vec<Value> = rows
            .iter()
            .map(|tx| {
                json!({
                    "txid": tx.txid,
                    "confirmed": tx.confirmed,
                    "block_height": tx.block_height,
                    "fee_sats": tx.fee_sats,
                    "net_sats": tx.net_sats,
                })
            })
            .collect();
        Ok(json!({ "transactions": transactions }))
    }

    async fn fee_estimates(&mut self) -> Result<Value, String> {
        let body = self.esplora_get("/fee-estimates").await?;
        let estimates = parse_fee_estimates(&body)?;
        let chosen = pick_feerate(&estimates, self.config.fee_target_blocks)?;
        Ok(json!({
            "target_blocks": self.config.fee_target_blocks,
            "feerate_sat_vb": chosen,
            "estimates": estimates,
        }))
    }

    async fn spend_log(&mut self, limit: u32) -> Result<Value, String> {
        let reply = guard_call(self.ctx, &GuardOp::SpendLog { limit }).await?;
        match reply {
            GuardReply::Log { spends } => Ok(json!({ "spends": spends })),
            GuardReply::Error { message } => Err(message),
            _ => Err("spend guard returned an unexpected payload".into()),
        }
    }

    async fn send(
        &mut self,
        to: &str,
        sats: u64,
        feerate: Option<u64>,
        broadcast: bool,
        request_id: Option<String>,
    ) -> Result<Value, String> {
        let wallet = self.wallet()?;
        if broadcast {
            wallet.fingerprint_ok(self.config.expected_fingerprint)?;
        }
        let dest = parse_address(to, self.config.network)?;
        let coins = self.collect_utxos(&wallet).await?;
        let feerate = match feerate {
            Some(rate) => rate,
            None => self.chosen_feerate().await?,
        };
        let change_index = self.next_change(&wallet).await?;
        let change = wallet.derive(ChainKind::Change, change_index)?.address;
        let built = build_payment(&Payment {
            script: self.config.script,
            fingerprint: wallet.fingerprint(),
            coins: &coins,
            dest: &dest,
            amount: sats,
            feerate,
            change: &change,
            max_input_sats: self.config.max_tx_input_sats,
        })?;
        let input_sats = transaction_input_sats(&built.psbt)?;
        enforce_input_cap(input_sats, self.config.max_tx_input_sats)?;
        if !broadcast {
            return Ok(json!({
                "broadcast": false,
                "signed": false,
                "input_sats": input_sats,
                "fee_sats": built.fee_sats,
                "feerate_sat_vb": built.feerate_sat_vb,
                "vsize": built.vsize,
                "outputs": built.outputs,
                "psbt": psbt_to_base64(&built.psbt),
                "used_unconfirmed": built.used_unconfirmed,
            }));
        }
        let mut psbt = built.psbt;
        sign_psbt(&wallet, &mut psbt, self.config.max_tx_input_sats)?;
        let (txid, hex) = extract_signed(&psbt)?;
        let warning = self
            .record_spend(
                &txid,
                input_sats,
                &dest.to_string(),
                built.fee_sats,
                SpendKind::Send,
                request_id,
            )
            .await;
        if let Err(err) = self.broadcast_hex(&hex).await {
            return Err(join_log_warning(&err, warning));
        }
        Ok(attach_log_warning(
            json!({
                "broadcast": true,
                "signed": true,
                "txid": txid,
                "input_sats": input_sats,
                "fee_sats": built.fee_sats,
                "feerate_sat_vb": built.feerate_sat_vb,
                "vsize": built.vsize,
                "outputs": built.outputs,
                "used_unconfirmed": built.used_unconfirmed,
            }),
            warning,
        ))
    }

    async fn sign_psbt(
        &mut self,
        encoded: &str,
        broadcast: bool,
        request_id: Option<String>,
    ) -> Result<Value, String> {
        let wallet = self.wallet()?;
        wallet.fingerprint_ok(self.config.expected_fingerprint)?;
        let mut psbt = psbt_from_base64(encoded)?;
        let input_sats = transaction_input_sats(&psbt)?;
        enforce_input_cap(input_sats, self.config.max_tx_input_sats)?;
        let (cache, _, _) = self.discover(&wallet).await?;
        let owned = owned_scripts(&wallet, &cache, &psbt, self.config.max_scan_index)?;
        annotate_owned_inputs(&wallet, &mut psbt, &owned)?;
        let inspection = inspect_psbt(
            &psbt,
            &owned,
            self.config.script,
            self.config.network.bitcoin(),
        )?;
        sign_psbt(&wallet, &mut psbt, self.config.max_tx_input_sats)?;
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let warning = self
            .record_spend(
                &txid,
                input_sats,
                &inspection.dest,
                inspection.fee_sats,
                SpendKind::Sign,
                request_id,
            )
            .await;
        if broadcast {
            if !inspection.broadcastable_after_sign {
                return Err(join_log_warning("psbt is not fully signed", warning));
            }
            let (_, hex) = extract_signed(&psbt)?;
            if let Err(err) = self.broadcast_hex(&hex).await {
                return Err(join_log_warning(&err, warning));
            }
        }
        Ok(attach_log_warning(
            json!({
                "broadcast": broadcast,
                "signed": true,
                "txid": txid,
                "input_sats": input_sats,
                "fee_sats": inspection.fee_sats,
                "vsize": inspection.vsize,
                "dest": inspection.dest,
                "psbt": psbt_to_base64(&psbt),
            }),
            warning,
        ))
    }

    async fn discover(
        &mut self,
        wallet: &Wallet,
    ) -> Result<
        (
            ScanCache,
            BTreeMap<u32, AddressStats>,
            BTreeMap<u32, AddressStats>,
        ),
        String,
    > {
        let cache = self.scan_cache().await?;
        let issued_external = cache.receive_cursor;
        let (external, ext_stats) = self
            .probe(
                wallet,
                ChainKind::External,
                &cache.used_external,
                issued_external,
            )
            .await?;
        let (change, chg_stats) = self
            .probe(wallet, ChainKind::Change, &cache.used_change, 0)
            .await?;
        let reply = guard_call(
            self.ctx,
            &GuardOp::MergeScan {
                used_external: external,
                used_change: change,
            },
        )
        .await?;
        let GuardReply::Scan { cache } = reply else {
            return Err("spend guard did not store the scan".into());
        };
        Ok((cache, ext_stats, chg_stats))
    }

    async fn probe(
        &mut self,
        wallet: &Wallet,
        chain: ChainKind,
        used: &[u32],
        issued_until: u32,
    ) -> Result<(Vec<u32>, BTreeMap<u32, AddressStats>), String> {
        let mut probed = BTreeMap::new();
        let mut stats = BTreeMap::new();
        let mut newly = Vec::new();
        loop {
            match next_probe(
                used,
                self.config.gap_limit,
                self.config.max_scan_index,
                &probed,
                issued_until,
            ) {
                ProbeStep::Done => return Ok((newly, stats)),
                ProbeStep::Exceeded { index } => {
                    return Err(format!("scan exceeded MAX_SCAN_INDEX at {index}"));
                }
                ProbeStep::Probe(index) => {
                    let derived = wallet.derive(chain, index)?;
                    let body = self
                        .esplora_get(&format!("/address/{}", derived.address))
                        .await?;
                    let parsed = parse_address_stats(&body)?;
                    if parsed.used {
                        newly.push(index);
                    }
                    probed.insert(index, parsed.used);
                    stats.insert(index, parsed);
                }
            }
        }
    }

    async fn stats(
        &mut self,
        wallet: &Wallet,
        chain: ChainKind,
        index: u32,
        known: &mut BTreeMap<u32, AddressStats>,
    ) -> Result<AddressStats, String> {
        if let Some(stats) = known.get(&index) {
            return Ok(stats.clone());
        }
        let derived = wallet.derive(chain, index)?;
        let body = self
            .esplora_get(&format!("/address/{}", derived.address))
            .await?;
        let parsed = parse_address_stats(&body)?;
        known.insert(index, parsed.clone());
        Ok(parsed)
    }

    async fn collect_utxos(&mut self, wallet: &Wallet) -> Result<Vec<Coin>, String> {
        let (cache, _, _) = self.discover(wallet).await?;
        let mut coins = Vec::new();
        for (chain, indexes) in [
            (ChainKind::External, cache.used_external.clone()),
            (ChainKind::Change, cache.used_change.clone()),
        ] {
            for index in indexes {
                let derived = wallet.derive(chain, index)?;
                let body = self
                    .esplora_get(&format!("/address/{}/utxo", derived.address))
                    .await?;
                for utxo in parse_utxos(&body)? {
                    coins.push(coin_from(wallet, chain, index, utxo)?);
                }
            }
        }
        Ok(coins)
    }

    async fn next_change(&mut self, wallet: &Wallet) -> Result<u32, String> {
        let cache = self.scan_cache().await?;
        let mut index = 0u32;
        while cache.used_change.binary_search(&index).is_ok() {
            index = index.saturating_add(1);
        }
        let _ = wallet;
        Ok(index)
    }

    async fn chosen_feerate(&mut self) -> Result<u64, String> {
        let body = self.esplora_get("/fee-estimates").await?;
        let estimates = parse_fee_estimates(&body)?;
        pick_feerate(&estimates, self.config.fee_target_blocks)
    }

    async fn record_spend(
        &mut self,
        txid: &str,
        input_sats: u64,
        dest: &str,
        fee_sats: u64,
        kind: SpendKind,
        _request_id: Option<String>,
    ) -> Option<String> {
        let record = SpendRecord {
            txid: txid.to_string(),
            input_sats,
            dest: dest.to_string(),
            fee_sats,
            at_ms: Date::now().as_millis(),
            client: self.client.clone(),
            kind,
        };
        let mut detail = "spend guard unavailable".to_string();
        for _ in 0..2 {
            match guard_call(
                self.ctx,
                &GuardOp::AppendSpend {
                    record: record.clone(),
                },
            )
            .await
            {
                Ok(GuardReply::Appended) => return None,
                Ok(GuardReply::Error { message }) => detail = message,
                Err(message) => detail = message,
                Ok(_) => detail = "spend guard returned an unexpected payload".into(),
            }
        }
        Some(unlogged_spend_warning(&detail))
    }

    async fn broadcast_hex(&mut self, hex: &str) -> Result<(), String> {
        match self.post_broadcast(hex).await {
            BroadcastVerdict::Accepted => Ok(()),
            BroadcastVerdict::Rejected { detail } => Err(format!("broadcast rejected: {detail}")),
            BroadcastVerdict::Unknown { detail } => Err(detail),
        }
    }

    async fn scan_cache(&mut self) -> Result<ScanCache, String> {
        match guard_call(self.ctx, &GuardOp::GetScan).await? {
            GuardReply::Scan { cache } => Ok(cache),
            GuardReply::Error { message } => Err(message),
            _ => Err("spend guard returned an unexpected payload".into()),
        }
    }

    async fn esplora_get(&mut self, path: &str) -> Result<String, String> {
        self.esplora(false, path, None, "application/json").await
    }

    async fn post_broadcast(&mut self, body: &str) -> BroadcastVerdict {
        let mut attempts = Vec::new();
        for backend in self.config.backends.clone() {
            let bearer = if backend.oauth {
                match self.oauth_token().await {
                    Ok(token) => Some(token),
                    Err(err) => {
                        attempts.push(RawAttempt::Transport { message: err });
                        continue;
                    }
                }
            } else {
                None
            };
            let url = format!("{}/tx", backend.base.trim_end_matches('/'));
            match self
                .http(
                    true,
                    &url,
                    Some(body.to_string()),
                    "text/plain",
                    bearer.as_deref(),
                )
                .await
            {
                Ok((status, text)) => attempts.push(RawAttempt::Http { status, body: text }),
                Err(err) => attempts.push(RawAttempt::Transport { message: err }),
            }
            if !matches!(fold_broadcast(&attempts), BroadcastVerdict::Unknown { .. }) {
                break;
            }
        }
        fold_broadcast(&attempts)
    }

    async fn esplora(
        &mut self,
        post: bool,
        path: &str,
        body: Option<String>,
        content_type: &str,
    ) -> Result<String, String> {
        let mut last = "all esplora backends failed".to_string();
        let backends = self.config.backends.clone();
        for backend in backends {
            let bearer = if backend.oauth {
                match self.oauth_token().await {
                    Ok(token) => Some(token),
                    Err(err) => {
                        last = err;
                        continue;
                    }
                }
            } else {
                None
            };
            let url = format!("{}{path}", backend.base.trim_end_matches('/'));
            let (status, text) = match self
                .http(post, &url, body.clone(), content_type, bearer.as_deref())
                .await
            {
                Ok(pair) => pair,
                Err(err) => {
                    last = err;
                    continue;
                }
            };
            match classify_attempt(false, status, &text) {
                AttemptClass::Success => return Ok(text),
                AttemptClass::Continue { note } => last = note,
                AttemptClass::Rejected { detail, .. } => return Err(detail),
            }
        }
        Err(last)
    }

    async fn oauth_token(&mut self) -> Result<String, String> {
        let now = Date::now().as_millis();
        if let Ok(GuardReply::Oauth {
            access_token,
            exp_ms,
        }) = guard_call(self.ctx, &GuardOp::GetOauth).await
        {
            if exp_ms > now.saturating_add(15_000) && !access_token.is_empty() {
                return Ok(access_token);
            }
        }
        let raw =
            secret(self.ctx, "BLOCKSTREAM_API_KEY").ok_or("BLOCKSTREAM_API_KEY is missing")?;
        let (client_id, client_secret) = parse_api_key(&raw)?;
        let form = form_encode(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "openid"),
        ]);
        let (status, text) = self
            .http(
                true,
                TOKEN_URL,
                Some(form),
                "application/x-www-form-urlencoded",
                None,
            )
            .await?;
        if status != 200 {
            return Err("blockstream token request failed".into());
        }
        let parsed = parse_token_response(&text)?;
        let exp_ms = now.saturating_add(
            parsed
                .expires_in_secs
                .saturating_mul(1000)
                .saturating_sub(30_000),
        );
        let _ = guard_call(
            self.ctx,
            &GuardOp::PutOauth {
                access_token: parsed.access_token.clone(),
                exp_ms,
            },
        )
        .await;
        Ok(parsed.access_token)
    }

    async fn http(
        &mut self,
        post: bool,
        url: &str,
        body: Option<String>,
        content_type: &str,
        bearer: Option<&str>,
    ) -> Result<(u16, String), String> {
        if self.calls >= self.config.max_chain_calls {
            return Err(
                "chain call budget exhausted; raise MAX_CHAIN_CALLS or lower GAP_LIMIT".into(),
            );
        }
        self.calls += 1;
        let headers = Headers::new();
        headers
            .set("accept", "application/json")
            .map_err(|_| "could not set headers")?;
        headers
            .set("content-type", content_type)
            .map_err(|_| "could not set headers")?;
        if let Some(token) = bearer {
            let value = format!("Bearer {token}");
            headers
                .set("authorization", &value)
                .map_err(|_| "could not set headers")?;
        }
        let mut init = RequestInit::new();
        init.with_method(if post { Method::Post } else { Method::Get });
        init.with_headers(headers);
        if let Some(body) = &body {
            init.with_body(Some(wasm_bindgen::JsValue::from_str(body)));
        }
        let request = Request::new_with_init(url, &init).map_err(|_| "chain request failed")?;
        let mut response = Fetch::Request(request)
            .send()
            .await
            .map_err(|_| "chain request failed")?;
        let status = response.status_code();
        let text = response
            .text()
            .await
            .map_err(|_| "chain response was not text")?;
        Ok((status, text))
    }
}

fn coin_from(wallet: &Wallet, chain: ChainKind, index: u32, utxo: Utxo) -> Result<Coin, String> {
    let derived = wallet.derive(chain, index)?;
    Ok(Coin {
        txid: crate::tx::parse_txid(&utxo.txid)?,
        vout: utxo.vout,
        value: utxo.value,
        script_pubkey: derived.address.script_pubkey(),
        path: derived.path,
        public_key: derived.public_key,
        confirmed: utxo.confirmed,
    })
}

fn owned_scripts(
    wallet: &Wallet,
    cache: &ScanCache,
    psbt: &Psbt,
    max_index: u32,
) -> Result<BTreeMap<ScriptBuf, (ChainKind, u32)>, String> {
    let mut indexes = BTreeMap::<ChainKind, BTreeSet<u32>>::new();
    let extent = |used: &[u32]| {
        used.iter()
            .copied()
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(cache.receive_cursor)
    };
    for index in 0..=extent(&cache.used_external).min(max_index) {
        indexes
            .entry(ChainKind::External)
            .or_default()
            .insert(index);
    }
    for index in 0..=extent(&cache.used_change).min(max_index) {
        indexes.entry(ChainKind::Change).or_default().insert(index);
    }
    for (chain, index) in indexes_from_origins(wallet, psbt) {
        indexes.entry(chain).or_default().insert(index);
    }
    let mut owned = BTreeMap::new();
    for (chain, set) in indexes {
        for index in set {
            let derived = wallet.derive(chain, index)?;
            owned.insert(derived.address.script_pubkey(), (chain, index));
        }
    }
    Ok(owned)
}

fn load_config(ctx: &RouteContext<()>) -> Result<Config, String> {
    let raw = RawConfig {
        network: var_string(ctx, "NETWORK"),
        script: var_string(ctx, "SCRIPT"),
        account: var_string(ctx, "ACCOUNT"),
        gap_limit: var_string(ctx, "GAP_LIMIT"),
        max_scan_index: var_string(ctx, "MAX_SCAN_INDEX"),
        max_chain_calls: var_string(ctx, "MAX_CHAIN_CALLS"),
        fee_target_blocks: var_string(ctx, "FEE_TARGET_BLOCKS"),
        max_tx_input_sats: var_string(ctx, "MAX_TX_INPUT_SATS"),
        esplora_urls: var_string(ctx, "ESPLORA_URLS"),
        expected_fingerprint: var_string(ctx, "EXPECTED_FINGERPRINT"),
        access_team_domain: var_string(ctx, "ACCESS_TEAM_DOMAIN"),
        access_aud: var_string(ctx, "ACCESS_AUD"),
        have_blockstream_key: secret(ctx, "BLOCKSTREAM_API_KEY").is_some(),
    };
    Config::from_raw(&raw)
}

async fn authorize(
    req: &Request,
    ctx: &RouteContext<()>,
    config: &Config,
) -> Result<String, Response> {
    if let Some(access) = &config.access {
        let jwt = req
            .headers()
            .get("Cf-Access-Jwt-Assertion")
            .ok()
            .flatten()
            .ok_or_else(unauthorized)?;
        let jwks = match jwks_json(&access.jwks_url()).await {
            Ok(body) => body,
            Err(_) => return Err(unauthorized()),
        };
        let rules = AccessRules {
            issuer: access.issuer(),
            audience: access.aud.clone(),
        };
        let now = Date::now().as_millis() / 1000;
        if verify_access_jwt(&jwt, &jwks, &rules, now).is_err() {
            JWKS.with(|cache| *cache.borrow_mut() = None);
            let refreshed = jwks_json(&access.jwks_url())
                .await
                .map_err(|_| unauthorized())?;
            if verify_access_jwt(&jwt, &refreshed, &rules, now).is_err() {
                return Err(unauthorized());
            }
        }
    }
    let raw = secret(ctx, "MCP_CLIENT_TOKENS").ok_or_else(unauthorized)?;
    let clients = Clients::parse(&raw).map_err(|_| unauthorized())?;
    let token = bearer(req.headers()).ok_or_else(unauthorized)?;
    clients.identify(&token).ok_or_else(unauthorized)
}

async fn jwks_json(url: &str) -> Result<String, ()> {
    let now = Date::now().as_millis();
    let cached = JWKS.with(|cache| {
        cache.borrow().as_ref().and_then(|entry| {
            if entry.exp_ms > now {
                Some(entry.body.clone())
            } else {
                None
            }
        })
    });
    if let Some(body) = cached {
        return Ok(body);
    }
    let request = Request::new_with_init(url, &RequestInit::new()).map_err(|_| ())?;
    let mut response = Fetch::Request(request).send().await.map_err(|_| ())?;
    if response.status_code() != 200 {
        return Err(());
    }
    let body = response.text().await.map_err(|_| ())?;
    JWKS.with(|cache| {
        *cache.borrow_mut() = Some(JwksCache {
            exp_ms: now.saturating_add(3_600_000),
            body: body.clone(),
        });
    });
    Ok(body)
}

fn bearer(headers: &Headers) -> Option<String> {
    let value = headers.get("Authorization").ok().flatten()?;
    let mut parts = value.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token.to_string())
    } else {
        None
    }
}

fn secret(ctx: &RouteContext<()>, name: &str) -> Option<String> {
    ctx.secret(name)
        .ok()
        .map(|value| value.to_string())
        .filter(|value| !value.trim().is_empty())
}

fn var_string(ctx: &RouteContext<()>, name: &str) -> String {
    ctx.var(name)
        .ok()
        .map(|value| value.to_string())
        .unwrap_or_default()
}

async fn guard_call(ctx: &RouteContext<()>, op: &GuardOp) -> Result<GuardReply, String> {
    let namespace = ctx
        .durable_object("SPEND_GUARD")
        .map_err(|_| "SPEND_GUARD binding is missing")?;
    let stub = namespace
        .id_from_name("satchel")
        .map_err(|_| "spend guard id failed")?
        .get_stub()
        .map_err(|_| "spend guard stub failed")?;
    let body = serde_json::to_string(op).map_err(|_| "guard request failed")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(wasm_bindgen::JsValue::from_str(&body)));
    let request = Request::new_with_init("https://spend-guard.internal/", &init)
        .map_err(|_| "guard request failed")?;
    let mut response = stub
        .fetch_with_request(request)
        .await
        .map_err(|_| "spend guard unavailable")?;
    let text = response
        .text()
        .await
        .map_err(|_| "spend guard returned an unreadable response")?;
    serde_json::from_str(&text)
        .map_err(|_| "spend guard returned an unexpected payload".to_string())
}

fn unauthorized() -> Response {
    let headers = Headers::new();
    let _ = headers.set("content-type", "application/json");
    let _ = headers.set("www-authenticate", "Bearer");
    let _ = headers.set("cache-control", "no-store");
    Response::error(r#"{"error":"unauthorized"}"#, 401)
        .unwrap_or_else(|_| Response::empty().unwrap())
        .with_headers(headers)
}

fn json_bytes(status: u16, body: &str) -> Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "no-store")?;
    Ok(Response::ok(body)?
        .with_status(status)
        .with_headers(headers))
}

fn json_value(status: u16, body: &Value) -> Result<Response> {
    json_bytes(status, &body.to_string())
}

#[durable_object(fetch)]
pub struct SpendGuard {
    state: State,
}

impl DurableObject for SpendGuard {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let body = req.text().await?;
        let op: GuardOp = match serde_json::from_str(&body) {
            Ok(op) => op,
            Err(_) => {
                return reply(&GuardReply::Error {
                    message: "invalid guard request".into(),
                })
            }
        };
        let reply_body = match op {
            GuardOp::AppendSpend { record } => self.append_spend(record).await?,
            GuardOp::SpendLog { limit } => self.spend_log(limit).await?,
            GuardOp::GetScan => GuardReply::Scan {
                cache: self.scan().await?,
            },
            GuardOp::MergeScan {
                used_external,
                used_change,
            } => self.merge(used_external, used_change).await?,
            GuardOp::AllocateReceive {
                advance,
                max_index,
                gap,
            } => self.allocate(advance, max_index, gap).await?,
            GuardOp::GetOauth => match self.oauth().await? {
                Some(cache) => GuardReply::Oauth {
                    access_token: cache.access_token,
                    exp_ms: cache.exp_ms,
                },
                None => GuardReply::OauthMiss,
            },
            GuardOp::PutOauth {
                access_token,
                exp_ms,
            } => {
                self.state
                    .storage()
                    .put(
                        "oauth",
                        &OauthCache {
                            access_token,
                            exp_ms,
                        },
                    )
                    .await?;
                GuardReply::OauthMiss
            }
        };
        reply(&reply_body)
    }
}

impl SpendGuard {
    async fn append_spend(&self, record: SpendRecord) -> Result<GuardReply> {
        let now = Date::now().as_millis();
        self.state
            .storage()
            .transaction(move |tx| async move {
                let mut log: crate::guard::SpendLog = load_or_default(&tx, "spend").await?;
                log.append(record, now);
                tx.put("spend", log).await?;
                Ok(())
            })
            .await?;
        Ok(GuardReply::Appended)
    }

    async fn spend_log(&self, limit: u32) -> Result<GuardReply> {
        let log = self
            .state
            .storage()
            .get::<crate::guard::SpendLog>("spend")
            .await?
            .unwrap_or_default();
        Ok(GuardReply::Log {
            spends: log.recent(limit),
        })
    }

    async fn merge(&self, external: Vec<u32>, change: Vec<u32>) -> Result<GuardReply> {
        let slot = Rc::new(RefCell::new(None));
        let slot_write = slot.clone();
        self.state
            .storage()
            .transaction(move |tx| async move {
                let current: ScanCache = load_or_default(&tx, "scan").await?;
                let merged = merge_scan(&current, &external, &change);
                tx.put("scan", &merged).await?;
                *slot_write.borrow_mut() = Some(merged);
                Ok(())
            })
            .await?;
        let cache = slot
            .borrow_mut()
            .take()
            .ok_or_else(|| worker::Error::from("scan merge failed".to_string()))?;
        Ok(GuardReply::Scan { cache })
    }

    async fn allocate(&self, advance: bool, max_index: u32, gap: u32) -> Result<GuardReply> {
        let slot = Rc::new(RefCell::new(None));
        let slot_write = slot.clone();
        self.state
            .storage()
            .transaction(move |tx| async move {
                let mut cache: ScanCache = load_or_default(&tx, "scan").await?;
                match take_receive(&mut cache, advance, max_index, gap) {
                    Ok(index) => {
                        tx.put("scan", &cache).await?;
                        *slot_write.borrow_mut() = Some(Ok(index));
                    }
                    Err(message) => {
                        *slot_write.borrow_mut() = Some(Err(message));
                    }
                }
                Ok(())
            })
            .await?;
        let outcome = slot.borrow_mut().take();
        match outcome {
            Some(Ok(index)) => Ok(GuardReply::ReceiveIndex { index }),
            Some(Err(message)) => Ok(GuardReply::Error { message }),
            None => Err(worker::Error::from("address allocation failed".to_string())),
        }
    }

    async fn scan(&self) -> Result<ScanCache> {
        Ok(self
            .state
            .storage()
            .get::<ScanCache>("scan")
            .await?
            .unwrap_or_default())
    }

    async fn oauth(&self) -> Result<Option<OauthCache>> {
        self.state.storage().get::<OauthCache>("oauth").await
    }
}

async fn load_or_default<T>(tx: &worker::durable::Transaction, key: &str) -> Result<T>
where
    T: Default + serde::de::DeserializeOwned + serde::Serialize,
{
    match tx.get::<T>(key).await {
        Ok(value) => Ok(value),
        Err(err) if err.to_string().contains("No such value") => Ok(T::default()),
        Err(err) => Err(err),
    }
}

fn reply(body: &GuardReply) -> Result<Response> {
    json_value(200, &serde_json::to_value(body)?)
}
