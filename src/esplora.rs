use crate::wallet::NetworkKind;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backend {
    pub base: String,
    pub oauth: bool,
}

pub fn plan_backends(
    network: NetworkKind,
    custom_urls: &str,
    have_key: bool,
) -> Result<Vec<Backend>, String> {
    let custom: Vec<&str> = custom_urls
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .collect();
    if !custom.is_empty() {
        return Ok(custom
            .into_iter()
            .map(|url| {
                let base = url.trim_end_matches('/').to_string();
                let oauth = have_key && blockstream_enterprise_origin(&base);
                Backend { base, oauth }
            })
            .collect());
    }
    let mut backends = Vec::new();
    match network {
        NetworkKind::Mainnet => {
            if have_key {
                backends.push(oauth("https://enterprise.blockstream.info/api"));
            }
            backends.push(plain("https://blockstream.info/api"));
            backends.push(plain("https://mempool.space/api"));
        }
        NetworkKind::Testnet => {
            if have_key {
                backends.push(oauth("https://enterprise.blockstream.info/testnet/api"));
            }
            backends.push(plain("https://blockstream.info/testnet/api"));
            backends.push(plain("https://mempool.space/testnet/api"));
        }
        NetworkKind::Signet => {
            backends.push(plain("https://blockstream.info/signet/api"));
            backends.push(plain("https://mempool.space/signet/api"));
        }
        NetworkKind::Regtest => {
            return Err(
                "NETWORK=regtest needs ESPLORA_URLS pointing at your Esplora, for example http://127.0.0.1:3000"
                    .into(),
            );
        }
    }
    Ok(backends)
}

fn plain(base: &str) -> Backend {
    Backend {
        base: base.to_string(),
        oauth: false,
    }
}

fn oauth(base: &str) -> Backend {
    Backend {
        base: base.to_string(),
        oauth: true,
    }
}

pub fn blockstream_enterprise_origin(url: &str) -> bool {
    let Some(rest) = url
        .get(8..)
        .filter(|_| url.len() >= 8 && url[..8].eq_ignore_ascii_case("https://"))
    else {
        return false;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return false;
    }
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = match hostport.rsplit_once(':') {
        Some((name, port)) if !name.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => hostport,
    };
    host.eq_ignore_ascii_case("enterprise.blockstream.info")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressStats {
    pub confirmed_sats: i64,
    pub unconfirmed_sats: i64,
    pub used: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub confirmed: bool,
}

pub fn parse_address_stats(body: &str) -> Result<AddressStats, String> {
    #[derive(Deserialize)]
    struct Stats {
        funded_txo_sum: u64,
        spent_txo_sum: u64,
        tx_count: u64,
    }
    #[derive(Deserialize)]
    struct Body {
        chain_stats: Stats,
        mempool_stats: Stats,
    }
    let parsed: Body =
        serde_json::from_str(body).map_err(|_| "address response was not esplora json")?;
    Ok(AddressStats {
        confirmed_sats: net(
            &parsed.chain_stats.funded_txo_sum,
            &parsed.chain_stats.spent_txo_sum,
        ),
        unconfirmed_sats: net(
            &parsed.mempool_stats.funded_txo_sum,
            &parsed.mempool_stats.spent_txo_sum,
        ),
        used: parsed.chain_stats.tx_count + parsed.mempool_stats.tx_count > 0,
    })
}

fn net(funded: &u64, spent: &u64) -> i64 {
    *funded as i64 - *spent as i64
}

pub fn parse_utxos(body: &str) -> Result<Vec<Utxo>, String> {
    #[derive(Deserialize)]
    struct Status {
        confirmed: bool,
    }
    #[derive(Deserialize)]
    struct Row {
        txid: String,
        vout: u32,
        value: u64,
        status: Status,
    }
    let rows: Vec<Row> =
        serde_json::from_str(body).map_err(|_| "utxo response was not esplora json")?;
    Ok(rows
        .into_iter()
        .map(|row| Utxo {
            txid: row.txid,
            vout: row.vout,
            value: row.value,
            confirmed: row.status.confirmed,
        })
        .collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryTx {
    pub txid: String,
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub fee_sats: Option<u64>,
    pub net_sats: i64,
}

pub const CONFIRMED_PAGE: usize = 25;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPage {
    pub txs: Vec<HistoryTx>,
    pub next_confirmed: Option<String>,
}

pub fn parse_history_page(body: &str, ours: &[String]) -> Result<HistoryPage, String> {
    let rows: Vec<Value> =
        serde_json::from_str(body).map_err(|_| "history response was not esplora json")?;
    let mut out = Vec::new();
    let mut confirmed_count = 0usize;
    let mut last_confirmed = None;
    for row in rows {
        let txid = row
            .get("txid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if txid.is_empty() {
            continue;
        }
        let status = row.get("status");
        let confirmed = status
            .and_then(|status| status.get("confirmed"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let block_height = status
            .and_then(|status| status.get("block_height"))
            .and_then(Value::as_u64);
        if confirmed {
            confirmed_count += 1;
            last_confirmed = Some(txid.clone());
        }
        let fee_sats = row.get("fee").and_then(Value::as_u64);
        let mut net_sats = 0i64;
        if let Some(vins) = row.get("vin").and_then(Value::as_array) {
            for vin in vins {
                if let Some(prevout) = vin.get("prevout") {
                    if let Some(address) =
                        prevout.get("scriptpubkey_address").and_then(Value::as_str)
                    {
                        if ours.iter().any(|item| item == address) {
                            net_sats -=
                                prevout.get("value").and_then(Value::as_u64).unwrap_or(0) as i64;
                        }
                    }
                }
            }
        }
        if let Some(vouts) = row.get("vout").and_then(Value::as_array) {
            for vout in vouts {
                if let Some(address) = vout.get("scriptpubkey_address").and_then(Value::as_str) {
                    if ours.iter().any(|item| item == address) {
                        net_sats += vout.get("value").and_then(Value::as_u64).unwrap_or(0) as i64;
                    }
                }
            }
        }
        out.push(HistoryTx {
            txid,
            confirmed,
            block_height,
            fee_sats,
            net_sats,
        });
    }
    let next_confirmed = if confirmed_count >= CONFIRMED_PAGE {
        last_confirmed
    } else {
        None
    };
    Ok(HistoryPage {
        txs: out,
        next_confirmed,
    })
}

pub fn parse_fee_estimates(body: &str) -> Result<BTreeMap<u32, f64>, String> {
    let raw: serde_json::Map<String, Value> =
        serde_json::from_str(body).map_err(|_| "fee estimate response was not esplora json")?;
    let mut out = BTreeMap::new();
    for (key, value) in raw {
        let Ok(target) = key.parse::<u32>() else {
            continue;
        };
        let Some(rate) = value.as_f64() else {
            continue;
        };
        if rate.is_finite() && rate >= 0.0 {
            out.insert(target, rate);
        }
    }
    if out.is_empty() {
        return Err("fee estimates were empty".into());
    }
    Ok(out)
}

pub fn pick_feerate(estimates: &BTreeMap<u32, f64>, target_blocks: u32) -> Result<u64, String> {
    let mut best_le: Option<f64> = None;
    for (blocks, rate) in estimates {
        if *blocks <= target_blocks {
            best_le = Some(*rate);
        }
    }
    let rate = best_le.or_else(|| estimates.values().next().copied());
    let Some(rate) = rate else {
        return Err("fee estimates were empty".into());
    };
    if !rate.is_finite() || rate < 0.0 {
        return Err("fee estimate was not a number".into());
    }
    let ceil = rate.ceil();
    if ceil >= u64::MAX as f64 {
        return Err("fee estimate was too large".into());
    }
    Ok(ceil as u64)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in_secs: u64,
}

pub fn parse_token_response(body: &str) -> Result<TokenResponse, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| "token endpoint returned an unexpected payload")?;
    let access_token = value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or("token endpoint returned an unexpected payload")?
        .to_string();
    let expires_in_secs = value
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(300);
    Ok(TokenResponse {
        access_token,
        expires_in_secs,
    })
}

pub fn parse_api_key(raw: &str) -> Result<(String, String), String> {
    let raw = raw.trim();
    let (id, secret) = raw
        .split_once(':')
        .ok_or("BLOCKSTREAM_API_KEY must be client_id:client_secret")?;
    if id.is_empty() || secret.is_empty() {
        return Err("BLOCKSTREAM_API_KEY must be client_id:client_secret".into());
    }
    Ok((id.to_string(), secret.to_string()))
}

pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub fn failover_status(status: u16) -> bool {
    matches!(status, 401 | 403 | 404 | 408 | 429 | 500 | 502 | 503 | 504)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptClass {
    Success,
    Continue { note: String },
    Rejected { status: u16, detail: String },
}

pub fn classify_attempt(broadcast: bool, status: u16, body: &str) -> AttemptClass {
    if (200..300).contains(&status) {
        return AttemptClass::Success;
    }
    if broadcast && status == 400 {
        let detail: String = body.chars().take(180).collect();
        let trimmed = detail.trim();
        if trimmed.is_empty() || trimmed.to_ascii_lowercase().contains("<html") {
            return AttemptClass::Continue {
                note: format!("esplora returned {status}"),
            };
        }
        if already_accepted_broadcast(trimmed) {
            return AttemptClass::Success;
        }
        return AttemptClass::Rejected {
            status,
            detail: trimmed.to_string(),
        };
    }
    if failover_status(status) {
        return AttemptClass::Continue {
            note: format!("esplora returned {status}"),
        };
    }
    AttemptClass::Rejected {
        status,
        detail: format!("esplora returned {status}"),
    }
}

fn already_accepted_broadcast(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("txn-already") || lower.contains("already in") || lower.contains("already known")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BroadcastVerdict {
    Accepted,
    Rejected { detail: String },
    Unknown { detail: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawAttempt {
    Transport { message: String },
    Http { status: u16, body: String },
}

pub fn fold_broadcast(attempts: &[RawAttempt]) -> BroadcastVerdict {
    let mut indeterminate = false;
    let mut last = "all esplora backends failed".to_string();
    for attempt in attempts {
        match attempt {
            RawAttempt::Transport { message } => {
                indeterminate = true;
                last = message.clone();
            }
            RawAttempt::Http { status, body } => match classify_attempt(true, *status, body) {
                AttemptClass::Success => return BroadcastVerdict::Accepted,
                AttemptClass::Continue { note } => {
                    if failover_status(*status) || *status >= 500 {
                        indeterminate = true;
                    }
                    last = note;
                }
                AttemptClass::Rejected { detail, .. } => {
                    if indeterminate {
                        last = detail;
                    } else {
                        return BroadcastVerdict::Rejected { detail };
                    }
                }
            },
        }
    }
    BroadcastVerdict::Unknown { detail: last }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_with_a_key_tries_enterprise_then_public_apis() {
        let backends = plan_backends(NetworkKind::Mainnet, "", true).unwrap();
        assert_eq!(
            backends,
            vec![
                Backend {
                    base: "https://enterprise.blockstream.info/api".into(),
                    oauth: true
                },
                Backend {
                    base: "https://blockstream.info/api".into(),
                    oauth: false
                },
                Backend {
                    base: "https://mempool.space/api".into(),
                    oauth: false
                },
            ]
        );
    }

    #[test]
    fn public_networks_work_without_a_key_and_custom_urls_replace_defaults() {
        let testnet = plan_backends(NetworkKind::Testnet, "", false).unwrap();
        assert!(testnet.iter().all(|backend| !backend.oauth));
        assert_eq!(testnet[0].base, "https://blockstream.info/testnet/api");
        let signet = plan_backends(NetworkKind::Signet, "", true).unwrap();
        assert_eq!(signet[0].base, "https://blockstream.info/signet/api");
        assert!(!signet[0].oauth);
        let custom = plan_backends(
            NetworkKind::Regtest,
            "http://127.0.0.1:3000/, https://enterprise.blockstream.info/api",
            true,
        )
        .unwrap();
        assert_eq!(custom[0].base, "http://127.0.0.1:3000");
        assert!(!custom[0].oauth);
        assert!(custom[1].oauth);
        assert!(plan_backends(NetworkKind::Regtest, "", false).is_err());
    }

    #[test]
    fn address_utxo_history_and_fee_payloads_parse() {
        let stats = parse_address_stats(
            r#"{"chain_stats":{"funded_txo_sum":1000,"spent_txo_sum":200,"tx_count":2},"mempool_stats":{"funded_txo_sum":50,"spent_txo_sum":80,"tx_count":1}}"#,
        )
        .unwrap();
        assert_eq!(stats.confirmed_sats, 800);
        assert_eq!(stats.unconfirmed_sats, -30);
        assert!(stats.used);

        let unused = parse_address_stats(
            r#"{"chain_stats":{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":0},"mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":0}}"#,
        )
        .unwrap();
        assert!(!unused.used);

        let utxos =
            parse_utxos(r#"[{"txid":"aa","vout":1,"value":5000,"status":{"confirmed":true}}]"#)
                .unwrap();
        assert_eq!(utxos[0].value, 5000);
        assert!(utxos[0].confirmed);

        let ours = vec!["bc1qours".to_string()];
        let history = parse_history_page(
            r#"[{"txid":"bb","fee":120,"status":{"confirmed":false},"vin":[{"prevout":{"scriptpubkey_address":"bc1qours","value":2000}}],"vout":[{"scriptpubkey_address":"bc1qother","value":1800}]}]"#,
            &ours,
        )
        .unwrap();
        assert_eq!(history.txs[0].net_sats, -2000);
        assert_eq!(history.txs[0].fee_sats, Some(120));
        assert!(!history.txs[0].confirmed);

        let estimates = parse_fee_estimates(r#"{"2":5.1,"6":3.2}"#).unwrap();
        assert_eq!(pick_feerate(&estimates, 3).unwrap(), 6);
        assert_eq!(pick_feerate(&estimates, 1).unwrap(), 6);
    }

    #[test]
    fn token_payload_and_api_key_parse_without_echoing_secrets_on_failure() {
        let token =
            parse_token_response(r#"{"access_token":"header.payload.sig","expires_in":300}"#)
                .unwrap();
        assert_eq!(token.expires_in_secs, 300);
        assert_eq!(token.access_token, "header.payload.sig");
        let err = parse_token_response(r#"{"error":"super-secret-body"}"#).unwrap_err();
        assert!(!err.contains("super-secret-body"));
        let (id, secret) = parse_api_key("client:sec:ret").unwrap();
        assert_eq!(id, "client");
        assert_eq!(secret, "sec:ret");
        assert!(parse_api_key("nosecret").is_err());
        assert_eq!(
            form_encode(&[
                ("grant_type", "client_credentials"),
                ("client_secret", "a b")
            ]),
            "grant_type=client_credentials&client_secret=a%20b"
        );
        assert!(failover_status(429));
        assert!(!failover_status(400));
    }

    #[test]
    fn oauth_is_only_the_enterprise_https_host() {
        assert!(blockstream_enterprise_origin(
            "https://enterprise.blockstream.info/api"
        ));
        assert!(blockstream_enterprise_origin(
            "https://enterprise.blockstream.info:443/testnet/api"
        ));
        assert!(!blockstream_enterprise_origin(
            "https://enterprise.blockstream.info.attacker.example/api"
        ));
        assert!(!blockstream_enterprise_origin(
            "http://enterprise.blockstream.info/api"
        ));
        assert!(!blockstream_enterprise_origin(
            "https://attacker.example/enterprise.blockstream.info"
        ));
        let custom = plan_backends(
            NetworkKind::Mainnet,
            "https://enterprise.blockstream.info.attacker.example/api, https://enterprise.blockstream.info/api",
            true,
        )
        .unwrap();
        assert!(!custom[0].oauth);
        assert!(custom[1].oauth);
    }

    #[test]
    fn history_keeps_change_inside_the_wallet_and_pages_confirmed_txs() {
        let ours = vec!["bc1qrecv".to_string(), "bc1qchange".to_string()];
        let body = r#"[{"txid":"cc","fee":200,"status":{"confirmed":true,"block_height":10},"vin":[{"prevout":{"scriptpubkey_address":"bc1qrecv","value":5000}}],"vout":[{"scriptpubkey_address":"bc1qother","value":1000},{"scriptpubkey_address":"bc1qchange","value":3800}]}]"#;
        let page = parse_history_page(body, &ours).unwrap();
        assert_eq!(page.txs[0].net_sats, -1200);
        assert!(page.next_confirmed.is_none());
        let mut rows = Vec::new();
        for index in 0..25 {
            rows.push(format!(
                r#"{{"txid":"{index:02x}","status":{{"confirmed":true,"block_height":1}}}}"#
            ));
        }
        let full = format!("[{}]", rows.join(","));
        let page = parse_history_page(&full, &[]).unwrap();
        assert_eq!(page.next_confirmed.as_deref(), Some("18"));
    }

    #[test]
    fn transport_errors_fall_through_and_only_a_clean_reject_releases() {
        let verdict = fold_broadcast(&[
            RawAttempt::Transport {
                message: "chain request failed".into(),
            },
            RawAttempt::Http {
                status: 200,
                body: "txid".into(),
            },
        ]);
        assert_eq!(verdict, BroadcastVerdict::Accepted);

        let verdict = fold_broadcast(&[
            RawAttempt::Transport {
                message: "chain response was not text".into(),
            },
            RawAttempt::Http {
                status: 502,
                body: String::new(),
            },
        ]);
        assert!(matches!(verdict, BroadcastVerdict::Unknown { .. }));

        let verdict = fold_broadcast(&[RawAttempt::Http {
            status: 400,
            body: "sendrawtransaction RPC error: bad-txns-inputs-missingorspent".into(),
        }]);
        assert!(matches!(verdict, BroadcastVerdict::Rejected { .. }));

        let verdict = fold_broadcast(&[
            RawAttempt::Transport {
                message: "chain request failed".into(),
            },
            RawAttempt::Http {
                status: 400,
                body: "bad-txns-inputs-missingorspent".into(),
            },
        ]);
        assert!(matches!(verdict, BroadcastVerdict::Unknown { .. }));
    }

    #[test]
    fn a_transaction_the_backend_already_has_is_accepted() {
        for body in [
            "txn-already-in-mempool",
            "Transaction already in block chain",
        ] {
            assert_eq!(
                fold_broadcast(&[RawAttempt::Http {
                    status: 400,
                    body: body.into(),
                }]),
                BroadcastVerdict::Accepted
            );
        }
    }
}
