use crate::esplora::{plan_backends, Backend};
use crate::wallet::{parse_fingerprint, NetworkKind, ScriptKind};
use bitcoin::bip32::Fingerprint;

#[derive(Clone, Debug)]
pub struct AccessSpec {
    pub host: String,
    pub aud: String,
}

impl AccessSpec {
    pub fn issuer(&self) -> String {
        format!("https://{}", self.host)
    }

    pub fn jwks_url(&self) -> String {
        format!("https://{}/cdn-cgi/access/certs", self.host)
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub network: NetworkKind,
    pub script: ScriptKind,
    pub account: u32,
    pub gap_limit: u32,
    pub max_scan_index: u32,
    pub max_chain_calls: u32,
    pub fee_target_blocks: u32,
    pub max_tx_input_sats: u64,
    pub expected_fingerprint: Option<Fingerprint>,
    pub backends: Vec<Backend>,
    pub access: Option<AccessSpec>,
}

#[derive(Clone, Debug, Default)]
pub struct RawConfig {
    pub network: String,
    pub script: String,
    pub account: String,
    pub gap_limit: String,
    pub max_scan_index: String,
    pub max_chain_calls: String,
    pub fee_target_blocks: String,
    pub max_tx_input_sats: String,
    pub esplora_urls: String,
    pub expected_fingerprint: String,
    pub access_team_domain: String,
    pub access_aud: String,
    pub have_blockstream_key: bool,
}

impl Config {
    pub fn from_raw(raw: &RawConfig) -> Result<Self, String> {
        let network = NetworkKind::parse(&raw.network)?;
        let script = ScriptKind::parse(&raw.script)?;
        let account = parse_u32(&raw.account, 0, "ACCOUNT")?;
        let gap_limit = bounded(
            parse_u32(&raw.gap_limit, 20, "GAP_LIMIT")?,
            1,
            100,
            "GAP_LIMIT",
        )?;
        let max_scan_index = bounded(
            parse_u32(&raw.max_scan_index, 200, "MAX_SCAN_INDEX")?,
            gap_limit,
            10_000,
            "MAX_SCAN_INDEX",
        )?;
        let max_chain_calls = bounded(
            parse_u32(&raw.max_chain_calls, 80, "MAX_CHAIN_CALLS")?,
            10,
            900,
            "MAX_CHAIN_CALLS",
        )?;
        let fee_target_blocks = bounded(
            parse_u32(&raw.fee_target_blocks, 3, "FEE_TARGET_BLOCKS")?,
            1,
            1008,
            "FEE_TARGET_BLOCKS",
        )?;
        let max_tx_input_sats = parse_u64(&raw.max_tx_input_sats, 100_000, "MAX_TX_INPUT_SATS")?;
        if max_tx_input_sats == 0 {
            return Err("MAX_TX_INPUT_SATS must be greater than zero".into());
        }
        let expected_fingerprint = if raw.expected_fingerprint.trim().is_empty() {
            None
        } else {
            Some(parse_fingerprint(&raw.expected_fingerprint)?)
        };
        let backends = plan_backends(network, &raw.esplora_urls, raw.have_blockstream_key)?;
        let access = access_spec(&raw.access_team_domain, &raw.access_aud)?;
        Ok(Self {
            network,
            script,
            account,
            gap_limit,
            max_scan_index,
            max_chain_calls,
            fee_target_blocks,
            max_tx_input_sats,
            expected_fingerprint,
            backends,
            access,
        })
    }
}

fn access_spec(domain: &str, aud: &str) -> Result<Option<AccessSpec>, String> {
    let domain = domain.trim();
    let aud = aud.trim();
    if domain.is_empty() && aud.is_empty() {
        return Ok(None);
    }
    if domain.is_empty() || aud.is_empty() {
        return Err("set both ACCESS_TEAM_DOMAIN and ACCESS_AUD, or leave both empty".into());
    }
    Ok(Some(AccessSpec {
        host: crate::auth::team_host(domain)?,
        aud: aud.to_string(),
    }))
}

fn parse_u32(value: &str, default: u32, name: &str) -> Result<u32, String> {
    if value.trim().is_empty() {
        return Ok(default);
    }
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("{name} must be an integer"))
}

fn parse_u64(value: &str, default: u64, name: &str) -> Result<u64, String> {
    if value.trim().is_empty() {
        return Ok(default);
    }
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an integer"))
}

fn bounded(value: u32, min: u32, max: u32, name: &str) -> Result<u32, String> {
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_mainnet_bip84_with_the_input_cap() {
        let config = Config::from_raw(&RawConfig::default()).unwrap();
        assert_eq!(config.network, NetworkKind::Mainnet);
        assert_eq!(config.script, ScriptKind::Bip84);
        assert_eq!(config.gap_limit, 20);
        assert_eq!(config.max_tx_input_sats, 100_000);
        assert!(config.expected_fingerprint.is_none());
        assert!(config.access.is_none());
        assert_eq!(config.backends.len(), 2);
    }

    #[test]
    fn signet_taproot_and_access_parse() {
        let mut raw = RawConfig {
            network: "signet".into(),
            script: "bip86".into(),
            gap_limit: "10".into(),
            access_team_domain: "example".into(),
            access_aud: "aud-tag".into(),
            expected_fingerprint: "73c5da0a".into(),
            ..RawConfig::default()
        };
        let config = Config::from_raw(&raw).unwrap();
        assert_eq!(config.network, NetworkKind::Signet);
        assert_eq!(config.script, ScriptKind::Bip86);
        assert_eq!(
            config.access.unwrap().jwks_url(),
            "https://example.cloudflareaccess.com/cdn-cgi/access/certs"
        );
        raw.access_aud.clear();
        assert!(Config::from_raw(&raw).is_err());
    }
}
