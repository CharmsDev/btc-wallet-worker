use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, Verification};
use bitcoin::{Address, CompressedPublicKey, Network, Script, ScriptBuf};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Bitcoin(NetworkKind),
    Litecoin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainChoice {
    Configured,
    Litecoin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectName(&'static str);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayTo {
    script: ScriptBuf,
    text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl NetworkKind {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "mainnet" | "bitcoin" => Ok(Self::Mainnet),
            "testnet" | "testnet3" => Ok(Self::Testnet),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            _ => Err("NETWORK must be mainnet, testnet, signet, or regtest".into()),
        }
    }

    pub fn bitcoin(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Testnet => Network::Testnet,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }

    pub fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet | Self::Signet | Self::Regtest => 1,
        }
    }
}

impl fmt::Display for NetworkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptKind {
    Bip84,
    Bip86,
}

impl ScriptKind {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "bip84" | "wpkh" | "segwit" => Ok(Self::Bip84),
            "bip86" | "tr" | "taproot" => Ok(Self::Bip86),
            _ => Err("SCRIPT must be bip84 or bip86".into()),
        }
    }

    pub fn purpose(self) -> u32 {
        match self {
            Self::Bip84 => 84,
            Self::Bip86 => 86,
        }
    }
}

impl fmt::Display for ScriptKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bip84 => "bip84",
            Self::Bip86 => "bip86",
        })
    }
}

impl ChainChoice {
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("").trim().to_ascii_lowercase().as_str() {
            "" | "bitcoin" => Ok(Self::Configured),
            "litecoin" => Ok(Self::Litecoin),
            _ => Err("chain must be bitcoin or litecoin".into()),
        }
    }

    pub fn resolve(self, bitcoin: NetworkKind) -> Chain {
        match self {
            Self::Configured => Chain::Bitcoin(bitcoin),
            Self::Litecoin => Chain::Litecoin,
        }
    }
}

impl Chain {
    pub fn label(self) -> &'static str {
        match self {
            Self::Bitcoin(NetworkKind::Mainnet) => "mainnet",
            Self::Bitcoin(NetworkKind::Testnet) => "testnet",
            Self::Bitcoin(NetworkKind::Signet) => "signet",
            Self::Bitcoin(NetworkKind::Regtest) => "regtest",
            Self::Litecoin => "litecoin",
        }
    }

    pub fn coin_type(self) -> u32 {
        match self {
            Self::Bitcoin(network) => network.coin_type(),
            Self::Litecoin => 2,
        }
    }

    /// Smallest payment or change `send` will create.
    ///
    /// Bitcoin stays at 546. Litecoin Core sets `DUST_RELAY_TX_FEE` to 30_000
    /// litoshi/kvB, and a P2WPKH output is dust below `98 * 30_000 / 1000`.
    pub fn dust_limit(self) -> u64 {
        match self {
            Self::Bitcoin(_) => 546,
            Self::Litecoin => 2_940,
        }
    }

    /// Network argument for `Xpriv::new_master`.
    ///
    /// The HMAC key inside rust-bitcoin is `Bitcoin seed` for every network.
    /// This value selects extended-key version bytes. Litecoin uses mainnet bytes so the descriptor is an `xpub`.
    pub fn master_network(self) -> Network {
        match self {
            Self::Bitcoin(network) => network.bitcoin(),
            Self::Litecoin => Network::Bitcoin,
        }
    }

    pub fn idem_network_byte(self) -> u8 {
        match self {
            Self::Bitcoin(NetworkKind::Mainnet) => 0,
            Self::Bitcoin(NetworkKind::Testnet) => 1,
            Self::Bitcoin(NetworkKind::Signet) => 2,
            Self::Bitcoin(NetworkKind::Regtest) => 3,
            Self::Litecoin => 4,
        }
    }

    pub fn object_name(self) -> ObjectName {
        match self {
            Self::Bitcoin(_) => ObjectName("satchel"),
            Self::Litecoin => ObjectName("satchel-ltc"),
        }
    }

    pub fn pay_from_key<C: Verification>(
        self,
        script: ScriptKind,
        public_key: &PublicKey,
        secp: &Secp256k1<C>,
    ) -> Result<PayTo, String> {
        match self {
            Self::Bitcoin(network) => bitcoin_pay(script, public_key, secp, network),
            Self::Litecoin => litecoin_p2wpkh(public_key),
        }
    }

    pub fn parse_pay(self, text: &str) -> Result<PayTo, String> {
        match self {
            Self::Bitcoin(network) => parse_bitcoin(network, text),
            Self::Litecoin => parse_litecoin(text),
        }
    }

    pub fn label_script(self, script: &Script) -> String {
        match self {
            Self::Bitcoin(network) => Address::from_script(script, network.bitcoin())
                .map(|address| address.to_string())
                .unwrap_or_else(|_| hex::encode(script.as_bytes())),
            Self::Litecoin => litecoin_label(script),
        }
    }
}

impl ObjectName {
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

impl PayTo {
    pub fn script(&self) -> &ScriptBuf {
        &self.script
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

fn ltc_hrp() -> bitcoin::bech32::hrp::Hrp {
    bitcoin::bech32::hrp::Hrp::parse("ltc").expect("ltc")
}

fn bitcoin_pay<C: Verification>(
    script: ScriptKind,
    public_key: &PublicKey,
    secp: &Secp256k1<C>,
    network: NetworkKind,
) -> Result<PayTo, String> {
    let address = match script {
        ScriptKind::Bip84 => {
            let compressed = CompressedPublicKey::from_slice(&public_key.serialize())
                .map_err(|_| "public key is not compressed".to_string())?;
            Address::p2wpkh(&compressed, network.bitcoin())
        }
        ScriptKind::Bip86 => {
            let (xonly, _) = public_key.x_only_public_key();
            Address::p2tr(secp, xonly, None, network.bitcoin())
        }
    };
    Ok(PayTo {
        script: address.script_pubkey(),
        text: address.to_string(),
    })
}

fn litecoin_p2wpkh(public_key: &PublicKey) -> Result<PayTo, String> {
    let compressed = CompressedPublicKey::from_slice(&public_key.serialize())
        .map_err(|_| "public key is not compressed".to_string())?;
    let hash = compressed.wpubkey_hash();
    let script = ScriptBuf::new_p2wpkh(&hash);
    let text = bitcoin::bech32::segwit::encode_v0(ltc_hrp(), &hash.to_byte_array())
        .map_err(|_| "could not encode a litecoin address".to_string())?;
    Ok(PayTo { script, text })
}

fn parse_bitcoin(network: NetworkKind, text: &str) -> Result<PayTo, String> {
    let unchecked = Address::from_str(text.trim()).map_err(|_| "invalid address".to_string())?;
    let address = unchecked
        .require_network(network.bitcoin())
        .map_err(|_| format!("address is not valid for {network}"))?;
    Ok(PayTo {
        script: address.script_pubkey(),
        text: address.to_string(),
    })
}

fn parse_litecoin(text: &str) -> Result<PayTo, String> {
    let (hrp, version, program) =
        bitcoin::bech32::segwit::decode(text.trim()).map_err(|_| "invalid address".to_string())?;
    if hrp != ltc_hrp() || version.to_u8() != 0 || program.len() != 20 {
        return Err("address is not a litecoin native segwit address".into());
    }
    let witness_version =
        bitcoin::WitnessVersion::try_from(version).map_err(|_| "invalid address".to_string())?;
    let witness = bitcoin::WitnessProgram::new(witness_version, &program)
        .map_err(|_| "invalid address".to_string())?;
    if !witness.is_p2wpkh() {
        return Err("address is not a litecoin native segwit address".into());
    }
    let script = ScriptBuf::new_witness_program(&witness);
    let canonical = bitcoin::bech32::segwit::encode_v0(ltc_hrp(), &program)
        .map_err(|_| "invalid address".to_string())?;
    Ok(PayTo {
        script,
        text: canonical,
    })
}

fn litecoin_label(script: &Script) -> String {
    let Some(version) = script.witness_version() else {
        return hex::encode(script.as_bytes());
    };
    if version != bitcoin::WitnessVersion::V0 {
        return hex::encode(script.as_bytes());
    }
    let bytes = script.as_bytes();
    bitcoin::bech32::segwit::encode_v0(ltc_hrp(), &bytes[2..])
        .unwrap_or_else(|_| hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIP84_RECEIVE_0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const BIP84_PUBKEY: &str = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c";
    const LTC_RECEIVE_0: &str = "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh";

    #[test]
    fn encode_v0_with_hrp_bc_matches_the_published_bip84_string() {
        let bytes = hex::decode(BIP84_PUBKEY).unwrap();
        let pubkey = CompressedPublicKey::from_slice(&bytes).unwrap();
        let encoded = bitcoin::bech32::segwit::encode_v0(
            bitcoin::bech32::hrp::BC,
            &pubkey.wpubkey_hash().to_byte_array(),
        )
        .unwrap();
        assert_eq!(encoded, BIP84_RECEIVE_0);
        let address = Address::p2wpkh(&pubkey, Network::Bitcoin);
        assert_eq!(address.to_string(), BIP84_RECEIVE_0);
    }

    #[test]
    fn litecoin_parse_accepts_p2wpkh_and_rejects_other_scripts() {
        let pay = Chain::Litecoin.parse_pay(LTC_RECEIVE_0).unwrap();
        assert_eq!(pay.text(), LTC_RECEIVE_0);
        assert!(pay.script().is_p2wpkh());
        let mixed = Chain::Litecoin
            .parse_pay("LTC1QJMXNZ78NMC8NQ77WUXH25N2ES7RZM5C2RKK4WH")
            .unwrap();
        assert_eq!(mixed.text(), LTC_RECEIVE_0);
        assert_eq!(mixed.script(), pay.script());
        assert!(Chain::Litecoin.parse_pay(BIP84_RECEIVE_0).is_err());
        assert!(Chain::Litecoin
            .parse_pay("Ler4HNAEfwYhBmGXcFP2Po1NpRUEiK8km2")
            .is_err());
        let p2wsh = bitcoin::bech32::segwit::encode_v0(ltc_hrp(), &[0x11; 32]).unwrap();
        assert!(Chain::Litecoin.parse_pay(&p2wsh).is_err());
        let taproot = bitcoin::bech32::segwit::encode_v1(ltc_hrp(), &[0x02; 32]).unwrap();
        assert!(taproot.starts_with("ltc1p"), "{taproot}");
        assert!(Chain::Litecoin.parse_pay(&taproot).is_err());
    }

    #[test]
    fn chain_choice_blank_and_bitcoin_stay_configured_and_ltc_is_rejected() {
        assert_eq!(ChainChoice::parse(None).unwrap(), ChainChoice::Configured);
        assert_eq!(
            ChainChoice::parse(Some("")).unwrap(),
            ChainChoice::Configured
        );
        assert_eq!(
            ChainChoice::parse(Some(" bitcoin ")).unwrap(),
            ChainChoice::Configured
        );
        assert_eq!(
            ChainChoice::parse(Some("litecoin")).unwrap(),
            ChainChoice::Litecoin
        );
        assert!(ChainChoice::parse(Some("ltc")).is_err());
        assert!(ChainChoice::parse(Some("mainnet")).is_err());
        assert_eq!(
            ChainChoice::Litecoin.resolve(NetworkKind::Signet),
            Chain::Litecoin
        );
        assert_eq!(
            ChainChoice::Configured.resolve(NetworkKind::Signet),
            Chain::Bitcoin(NetworkKind::Signet)
        );
    }

    #[test]
    fn object_names_and_idempotency_bytes_stay_in_their_slots() {
        assert_eq!(
            Chain::Bitcoin(NetworkKind::Mainnet).object_name().as_str(),
            "satchel"
        );
        assert_eq!(
            Chain::Bitcoin(NetworkKind::Signet).object_name().as_str(),
            "satchel"
        );
        assert_eq!(Chain::Litecoin.object_name().as_str(), "satchel-ltc");
        assert_eq!(Chain::Bitcoin(NetworkKind::Mainnet).idem_network_byte(), 0);
        assert_eq!(Chain::Bitcoin(NetworkKind::Testnet).idem_network_byte(), 1);
        assert_eq!(Chain::Bitcoin(NetworkKind::Signet).idem_network_byte(), 2);
        assert_eq!(Chain::Bitcoin(NetworkKind::Regtest).idem_network_byte(), 3);
        assert_eq!(Chain::Litecoin.idem_network_byte(), 4);
        assert_eq!(Chain::Litecoin.label(), "litecoin");
        assert_eq!(Chain::Bitcoin(NetworkKind::Signet).label(), "signet");
        assert_eq!(Chain::Litecoin.master_network(), Network::Bitcoin);
        assert_eq!(Chain::Litecoin.coin_type(), 2);
        assert_eq!(Chain::Bitcoin(NetworkKind::Mainnet).dust_limit(), 546);
        assert_eq!(Chain::Litecoin.dust_limit(), 2_940);
    }
}
