use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::{Address, CompressedPublicKey, Network, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use zeroize::Zeroize;

#[cfg(test)]
pub const BIP84_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainKind {
    External,
    Change,
}

impl ChainKind {
    pub fn index(self) -> u32 {
        match self {
            Self::External => 0,
            Self::Change => 1,
        }
    }
}

pub struct Derived {
    pub address: Address,
    pub public_key: PublicKey,
    pub path: DerivationPath,
}

pub struct Wallet {
    master: Xpriv,
    account_xpub: Xpub,
    fingerprint: Fingerprint,
    network: NetworkKind,
    script: ScriptKind,
    account: u32,
    account_path: DerivationPath,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("fingerprint", &self.fingerprint.to_string())
            .field("network", &self.network)
            .field("script", &self.script)
            .field("account", &self.account)
            .finish()
    }
}

impl Wallet {
    pub fn open(
        mut mnemonic_words: String,
        network: NetworkKind,
        script: ScriptKind,
        account: u32,
    ) -> Result<Self, String> {
        let parsed = Mnemonic::parse(mnemonic_words.trim())
            .map_err(|_| "BTC_WALLET_SEED is not a valid BIP39 mnemonic".to_string());
        mnemonic_words.zeroize();
        let mnemonic = parsed?;
        let mut seed = mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(network.bitcoin(), &seed)
            .map_err(|_| "BTC_WALLET_SEED could not derive a master key".to_string());
        seed.zeroize();
        let master = master?;
        let account_path = DerivationPath::from_str(&format!(
            "m/{}'/{}'/{}'",
            script.purpose(),
            network.coin_type(),
            account
        ))
        .map_err(|_| "account path is invalid".to_string())?;
        let account_key = master
            .derive_priv(&secp, &account_path)
            .map_err(|_| "account path could not be derived".to_string())?;
        let account_xpub = Xpub::from_priv(&secp, &account_key);
        let fingerprint = master.fingerprint(&secp);
        Ok(Self {
            master,
            account_xpub,
            fingerprint,
            network,
            script,
            account,
            account_path,
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn network(&self) -> NetworkKind {
        self.network
    }

    pub fn script(&self) -> ScriptKind {
        self.script
    }

    pub fn account_path(&self) -> String {
        format!("m/{}", self.account_path)
    }

    pub fn account(&self) -> u32 {
        self.account
    }

    pub fn fingerprint_ok(&self, expected: Option<Fingerprint>) -> Result<(), String> {
        match expected {
            None => Ok(()),
            Some(expected) if expected == self.fingerprint => Ok(()),
            Some(_) => Err(format!(
                "seed fingerprint {} does not match EXPECTED_FINGERPRINT",
                self.fingerprint
            )),
        }
    }

    pub fn descriptor(&self, chain: ChainKind) -> String {
        let origin = format!(
            "[{}/{}'/{}'/{}']",
            self.fingerprint,
            self.script.purpose(),
            self.network.coin_type(),
            self.account
        );
        let xpub = self.account_xpub.to_string();
        match self.script {
            ScriptKind::Bip84 => format!("wpkh({origin}{xpub}/{}/{})", chain.index(), "*"),
            ScriptKind::Bip86 => format!("tr({origin}{xpub}/{}/{})", chain.index(), "*"),
        }
    }

    pub fn derive(&self, chain: ChainKind, index: u32) -> Result<Derived, String> {
        let path = DerivationPath::from_str(&format!(
            "m/{}'/{}'/{}'/{}/{}",
            self.script.purpose(),
            self.network.coin_type(),
            self.account,
            chain.index(),
            index
        ))
        .map_err(|_| "derivation path is invalid".to_string())?;
        let secp = Secp256k1::new();
        let child = self
            .master
            .derive_priv(&secp, &path)
            .map_err(|_| "derivation path could not be derived".to_string())?;
        let public_key = PublicKey::from_secret_key(&secp, &child.private_key);
        let address = match self.script {
            ScriptKind::Bip84 => {
                let compressed = CompressedPublicKey::from_slice(&public_key.serialize())
                    .map_err(|_| "public key is not compressed".to_string())?;
                Address::p2wpkh(&compressed, self.network.bitcoin())
            }
            ScriptKind::Bip86 => {
                let (xonly, _) = public_key.x_only_public_key();
                Address::p2tr(&secp, xonly, None, self.network.bitcoin())
            }
        };
        Ok(Derived {
            address,
            public_key,
            path,
        })
    }

    pub fn master_key(&self) -> &Xpriv {
        &self.master
    }
}

pub fn parse_fingerprint(value: &str) -> Result<Fingerprint, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("fingerprint is empty".into());
    }
    Fingerprint::from_str(value).map_err(|_| "EXPECTED_FINGERPRINT must be 8 hex characters".into())
}

pub fn parse_address(value: &str, network: NetworkKind) -> Result<Address, String> {
    let unchecked = Address::from_str(value.trim()).map_err(|_| "invalid address".to_string())?;
    unchecked
        .require_network(network.bitcoin())
        .map_err(|_| format!("address is not valid for {network}"))
}

pub fn xonly_of(public_key: &PublicKey) -> XOnlyPublicKey {
    public_key.x_only_public_key().0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip84_vector_matches_the_published_addresses() {
        let wallet = Wallet::open(
            BIP84_MNEMONIC.into(),
            NetworkKind::Mainnet,
            ScriptKind::Bip84,
            0,
        )
        .unwrap();
        let first = wallet.derive(ChainKind::External, 0).unwrap();
        let second = wallet.derive(ChainKind::External, 1).unwrap();
        let change = wallet.derive(ChainKind::Change, 0).unwrap();
        assert_eq!(
            first.address.to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            second.address.to_string(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(
            change.address.to_string(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
        assert_eq!(
            hex::encode(first.public_key.serialize()),
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        );
        assert_eq!(wallet.account_path(), "m/84'/0'/0'");
        assert!(!format!("{wallet:?}").contains("xprv"));
        assert!(!wallet.descriptor(ChainKind::External).contains("xprv"));
        assert!(wallet.descriptor(ChainKind::External).starts_with("wpkh("));
    }

    #[test]
    fn bip86_vector_matches_the_first_receive_address() {
        let wallet = Wallet::open(
            BIP84_MNEMONIC.into(),
            NetworkKind::Mainnet,
            ScriptKind::Bip86,
            0,
        )
        .unwrap();
        let first = wallet.derive(ChainKind::External, 0).unwrap();
        assert_eq!(
            first.address.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert!(wallet.descriptor(ChainKind::Change).starts_with("tr("));
        assert_eq!(wallet.account_path(), "m/86'/0'/0'");
    }

    #[test]
    fn testnet_uses_coin_type_one_and_rejects_mainnet_addresses() {
        let wallet = Wallet::open(
            BIP84_MNEMONIC.into(),
            NetworkKind::Testnet,
            ScriptKind::Bip84,
            0,
        )
        .unwrap();
        let address = wallet
            .derive(ChainKind::External, 0)
            .unwrap()
            .address
            .to_string();
        assert!(address.starts_with("tb1q"), "{address}");
        assert_eq!(wallet.account_path(), "m/84'/1'/0'");
        assert!(parse_address(
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            NetworkKind::Testnet
        )
        .is_err());
        assert!(parse_address(&address, NetworkKind::Testnet).is_ok());
        assert!(parse_address(&address, NetworkKind::Mainnet).is_err());
        let signet = parse_address(&address, NetworkKind::Signet);
        assert!(signet.is_ok());
    }

    #[test]
    fn regtest_addresses_stay_on_regtest() {
        let wallet = Wallet::open(
            BIP84_MNEMONIC.into(),
            NetworkKind::Regtest,
            ScriptKind::Bip84,
            0,
        )
        .unwrap();
        let address = wallet
            .derive(ChainKind::External, 0)
            .unwrap()
            .address
            .to_string();
        assert!(address.starts_with("bcrt1q"), "{address}");
        assert!(parse_address(&address, NetworkKind::Regtest).is_ok());
        assert!(parse_address(&address, NetworkKind::Signet).is_err());
    }

    #[test]
    fn a_bad_mnemonic_does_not_echo_the_input() {
        let err = Wallet::open(
            "zzzz not-a-seed".into(),
            NetworkKind::Mainnet,
            ScriptKind::Bip84,
            0,
        )
        .unwrap_err();
        assert!(!err.contains("zzzz"));
        assert!(err.contains("BTC_WALLET_SEED"));
    }

    #[test]
    fn expected_fingerprint_gates_signing() {
        let wallet = Wallet::open(
            BIP84_MNEMONIC.into(),
            NetworkKind::Mainnet,
            ScriptKind::Bip84,
            0,
        )
        .unwrap();
        assert!(wallet.fingerprint_ok(None).is_ok());
        assert!(wallet.fingerprint_ok(Some(wallet.fingerprint())).is_ok());
        let other = parse_fingerprint("00000000").unwrap();
        let err = wallet.fingerprint_ok(Some(other)).unwrap_err();
        assert!(err.contains("EXPECTED_FINGERPRINT"));
        assert!(!err.contains("abandon"));
    }
}
