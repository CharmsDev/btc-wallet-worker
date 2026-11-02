use crate::chain::{Chain, PayTo, ScriptKind};
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use zeroize::Zeroize;

#[cfg(test)]
pub const BIP84_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
    pub pay: PayTo,
    pub public_key: PublicKey,
    pub path: DerivationPath,
}

pub struct Wallet {
    master: Xpriv,
    account_xpub: Xpub,
    fingerprint: Fingerprint,
    chain: Chain,
    script: ScriptKind,
    account: u32,
    account_path: DerivationPath,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("fingerprint", &self.fingerprint.to_string())
            .field("chain", &self.chain)
            .field("script", &self.script)
            .field("account", &self.account)
            .finish()
    }
}

impl Wallet {
    pub fn open(
        mut mnemonic_words: String,
        chain: Chain,
        script: ScriptKind,
        account: u32,
    ) -> Result<Self, String> {
        let script = match chain {
            Chain::Litecoin => ScriptKind::Bip84,
            Chain::Bitcoin(_) => script,
        };
        let parsed = Mnemonic::parse(mnemonic_words.trim())
            .map_err(|_| "BTC_WALLET_SEED is not a valid BIP39 mnemonic".to_string());
        mnemonic_words.zeroize();
        let mnemonic = parsed?;
        let mut seed = mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(chain.master_network(), &seed)
            .map_err(|_| "BTC_WALLET_SEED could not derive a master key".to_string());
        seed.zeroize();
        let master = master?;
        let account_path = DerivationPath::from_str(&format!(
            "m/{}'/{}'/{}'",
            script.purpose(),
            chain.coin_type(),
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
            chain,
            script,
            account,
            account_path,
        })
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn chain(&self) -> Chain {
        self.chain
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
            self.chain.coin_type(),
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
            self.chain.coin_type(),
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
        let pay = self.chain.pay_from_key(self.script, &public_key, &secp)?;
        Ok(Derived {
            pay,
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

pub fn xonly_of(public_key: &PublicKey) -> XOnlyPublicKey {
    public_key.x_only_public_key().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::NetworkKind;

    fn open(chain: Chain, script: ScriptKind) -> Wallet {
        Wallet::open(BIP84_MNEMONIC.into(), chain, script, 0).unwrap()
    }

    #[test]
    fn bip84_vector_matches_the_published_addresses() {
        let wallet = open(Chain::Bitcoin(NetworkKind::Mainnet), ScriptKind::Bip84);
        let first = wallet.derive(ChainKind::External, 0).unwrap();
        let second = wallet.derive(ChainKind::External, 1).unwrap();
        let change = wallet.derive(ChainKind::Change, 0).unwrap();
        assert_eq!(
            first.pay.text(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            second.pay.text(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(
            change.pay.text(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
        assert_eq!(wallet.fingerprint().to_string(), "73c5da0a");
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
        let wallet = open(Chain::Bitcoin(NetworkKind::Mainnet), ScriptKind::Bip86);
        let first = wallet.derive(ChainKind::External, 0).unwrap();
        assert_eq!(
            first.pay.text(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(wallet.fingerprint().to_string(), "73c5da0a");
        assert!(wallet.descriptor(ChainKind::Change).starts_with("tr("));
        assert_eq!(wallet.account_path(), "m/86'/0'/0'");
    }

    #[test]
    fn litecoin_bip84_matches_the_published_receive_and_keeps_the_fingerprint() {
        let bitcoin = open(Chain::Bitcoin(NetworkKind::Mainnet), ScriptKind::Bip84);
        let litecoin = open(Chain::Litecoin, ScriptKind::Bip86);
        assert_eq!(litecoin.script(), ScriptKind::Bip84);
        assert_eq!(litecoin.fingerprint(), bitcoin.fingerprint());
        assert_eq!(litecoin.fingerprint().to_string(), "73c5da0a");
        assert_eq!(litecoin.account_path(), "m/84'/2'/0'");
        let receive = litecoin.derive(ChainKind::External, 0).unwrap();
        assert_eq!(format!("m/{}", receive.path), "m/84'/2'/0'/0/0");
        assert_eq!(
            receive.pay.text(),
            "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh"
        );
        assert_eq!(
            hex::encode(receive.public_key.serialize()),
            "02e49c9b9b5d0f127235dc26a0c252814c52fb333d651a946773f59d72c2da9904"
        );
        let change = litecoin.derive(ChainKind::Change, 0).unwrap();
        assert_eq!(
            change.pay.text(),
            "ltc1qyeljcy9v88jg8sqvnqh0m5q390xruc5r98q9yy"
        );
        assert_eq!(format!("m/{}", change.path), "m/84'/2'/0'/1/0");
        let descriptor = litecoin.descriptor(ChainKind::External);
        assert!(descriptor.starts_with("wpkh("));
        assert!(descriptor.contains("xpub"));
        assert!(!descriptor.contains("zpub"));
    }

    #[test]
    fn testnet_uses_coin_type_one_and_rejects_mainnet_addresses() {
        let wallet = open(Chain::Bitcoin(NetworkKind::Testnet), ScriptKind::Bip84);
        let address = wallet
            .derive(ChainKind::External, 0)
            .unwrap()
            .pay
            .text()
            .to_string();
        assert!(address.starts_with("tb1q"), "{address}");
        assert_eq!(wallet.account_path(), "m/84'/1'/0'");
        assert_eq!(wallet.fingerprint().to_string(), "73c5da0a");
        assert!(Chain::Bitcoin(NetworkKind::Testnet)
            .parse_pay("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
            .is_err());
        assert!(Chain::Bitcoin(NetworkKind::Testnet)
            .parse_pay(&address)
            .is_ok());
        assert!(Chain::Bitcoin(NetworkKind::Mainnet)
            .parse_pay(&address)
            .is_err());
        assert!(Chain::Bitcoin(NetworkKind::Signet)
            .parse_pay(&address)
            .is_ok());
    }

    #[test]
    fn regtest_addresses_stay_on_regtest() {
        let wallet = open(Chain::Bitcoin(NetworkKind::Regtest), ScriptKind::Bip84);
        let address = wallet
            .derive(ChainKind::External, 0)
            .unwrap()
            .pay
            .text()
            .to_string();
        assert!(address.starts_with("bcrt1q"), "{address}");
        assert!(Chain::Bitcoin(NetworkKind::Regtest)
            .parse_pay(&address)
            .is_ok());
        assert!(Chain::Bitcoin(NetworkKind::Signet)
            .parse_pay(&address)
            .is_err());
    }

    #[test]
    fn a_bad_mnemonic_does_not_echo_the_input() {
        let err = Wallet::open(
            "zzzz not-a-seed".into(),
            Chain::Bitcoin(NetworkKind::Mainnet),
            ScriptKind::Bip84,
            0,
        )
        .unwrap_err();
        assert!(!err.contains("zzzz"));
        assert!(err.contains("BTC_WALLET_SEED"));
    }

    #[test]
    fn expected_fingerprint_gates_signing() {
        let wallet = open(Chain::Bitcoin(NetworkKind::Mainnet), ScriptKind::Bip84);
        assert!(wallet.fingerprint_ok(None).is_ok());
        assert!(wallet.fingerprint_ok(Some(wallet.fingerprint())).is_ok());
        let other = parse_fingerprint("00000000").unwrap();
        let err = wallet.fingerprint_ok(Some(other)).unwrap_err();
        assert!(err.contains("EXPECTED_FINGERPRINT"));
        assert!(!err.contains("abandon"));
    }
}
