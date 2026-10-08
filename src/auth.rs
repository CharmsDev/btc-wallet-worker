use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const MIN_TOKEN_LEN: usize = 16;

#[derive(Clone, Debug)]
pub struct Clients {
    entries: Vec<(String, [u8; 32])>,
}

impl Clients {
    pub fn parse(json: &str) -> Result<Self, String> {
        let map: serde_json::Map<String, Value> = serde_json::from_str(json)
            .map_err(|_| "MCP_CLIENT_TOKENS must be a JSON object of name to token".to_string())?;
        if map.is_empty() {
            return Err("MCP_CLIENT_TOKENS must contain at least one client".into());
        }
        let mut entries = Vec::with_capacity(map.len());
        let mut seen = Vec::new();
        for (name, value) in map {
            let name = name.trim().to_string();
            if name.is_empty()
                || name.len() > 64
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(
                    "client names must be 1-64 characters of letters, digits, '-' or '_'".into(),
                );
            }
            let token = value
                .as_str()
                .ok_or_else(|| format!("token for client {name} must be a string"))?;
            if token.len() < MIN_TOKEN_LEN {
                return Err(format!(
                    "token for client {name} must be at least {MIN_TOKEN_LEN} characters"
                ));
            }
            let hash = hash_token(token);
            if seen
                .iter()
                .any(|other: &[u8; 32]| bool::from(hash.ct_eq(other)))
            {
                return Err("two clients must not share one token".into());
            }
            seen.push(hash);
            entries.push((name, hash));
        }
        Ok(Self { entries })
    }

    pub fn identify(&self, presented: &str) -> Option<String> {
        let hash = hash_token(presented);
        let mut found = None;
        for (name, stored) in &self.entries {
            if bool::from(hash.ct_eq(stored)) {
                found = Some(name.clone());
            }
        }
        found
    }
}

fn hash_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRules {
    pub issuer: String,
    pub audience: String,
}

pub fn verify_access_jwt(
    token: &str,
    jwks_json: &str,
    rules: &AccessRules,
    now_unix: u64,
) -> Result<(), String> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or("invalid access token")?;
    let payload_b64 = parts.next().ok_or("invalid access token")?;
    let sig_b64 = parts.next().ok_or("invalid access token")?;
    if parts.next().is_some() {
        return Err("invalid access token".into());
    }
    let header: Value = decode_json(header_b64)?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg != "RS256" {
        return Err("access token algorithm is not RS256".into());
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or("access token is missing kid")?;
    let payload: Value = decode_json(payload_b64)?;
    check_time(&payload, now_unix)?;
    check_issuer(&payload, &rules.issuer)?;
    check_audience(&payload, &rules.audience)?;
    let key = find_jwk(jwks_json, kid)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "invalid access token")?;
    let signature =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| "access token signature rejected")?;
    let verifying = VerifyingKey::<Sha256>::new(key);
    verifying
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "access token signature rejected".to_string())
}

fn decode_json(part: &str) -> Result<Value, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| "invalid access token")?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid access token".to_string())
}

fn check_time(payload: &Value, now_unix: u64) -> Result<(), String> {
    let exp = payload
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or("access token is missing exp")?;
    if exp + 60 < now_unix {
        return Err("access token expired".into());
    }
    if let Some(nbf) = payload.get("nbf").and_then(Value::as_u64) {
        if now_unix + 60 < nbf {
            return Err("access token is not valid yet".into());
        }
    }
    Ok(())
}

fn check_issuer(payload: &Value, issuer: &str) -> Result<(), String> {
    match payload.get("iss").and_then(Value::as_str) {
        Some(iss) if iss == issuer => Ok(()),
        _ => Err("access token issuer mismatch".into()),
    }
}

fn check_audience(payload: &Value, audience: &str) -> Result<(), String> {
    match payload.get("aud") {
        Some(Value::String(aud)) if aud == audience => Ok(()),
        Some(Value::Array(items)) if items.iter().any(|item| item.as_str() == Some(audience)) => {
            Ok(())
        }
        _ => Err("access token audience mismatch".into()),
    }
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    n: String,
    e: String,
    #[serde(default)]
    alg: Option<String>,
}

fn find_jwk(jwks_json: &str, kid: &str) -> Result<RsaPublicKey, String> {
    let jwks: Jwks = serde_json::from_str(jwks_json).map_err(|_| "access jwks is invalid")?;
    let jwk = jwks
        .keys
        .into_iter()
        .find(|key| key.kid == kid)
        .ok_or("access token key is unknown")?;
    if jwk.kty != "RSA" {
        return Err("access token key is not RSA".into());
    }
    if let Some(alg) = jwk.alg.as_deref() {
        if alg != "RS256" {
            return Err("access token key is not RS256".into());
        }
    }
    let n = URL_SAFE_NO_PAD
        .decode(jwk.n.as_bytes())
        .map_err(|_| "access jwks is invalid")?;
    let e = URL_SAFE_NO_PAD
        .decode(jwk.e.as_bytes())
        .map_err(|_| "access jwks is invalid")?;
    RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        .map_err(|_| "access jwks is invalid".to_string())
}

pub fn team_host(input: &str) -> Result<String, String> {
    let trimmed = input
        .trim()
        .trim_start_matches("https://")
        .trim_end_matches('/');
    if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains(' ') {
        return Err("ACCESS_TEAM_DOMAIN is invalid".into());
    }
    if trimmed.ends_with(".cloudflareaccess.com") {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("{trimmed}.cloudflareaccess.com"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::rand_core::OsRng;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    #[test]
    fn named_tokens_match_only_the_full_secret() {
        let clients =
            Clients::parse(r#"{"cursor":"cursor-token-aaaa","grok":"grok-token-bbbbbb"}"#).unwrap();
        assert_eq!(
            clients.identify("cursor-token-aaaa").as_deref(),
            Some("cursor")
        );
        assert_eq!(
            clients.identify("grok-token-bbbbbb").as_deref(),
            Some("grok")
        );
        assert_eq!(clients.identify("cursor-token-aaa"), None);
        assert_eq!(clients.identify("cursor-token-aaaa-extra"), None);
        assert_eq!(clients.identify(""), None);
        assert_eq!(clients.identify("not-a-client-token"), None);
    }

    #[test]
    fn short_and_duplicate_tokens_are_rejected() {
        assert!(Clients::parse(r#"{"local":"short"}"#).is_err());
        assert!(Clients::parse(r#"{"a":"same-token-value","b":"same-token-value"}"#).is_err());
        assert!(Clients::parse("{}").is_err());
    }

    #[test]
    fn access_jwt_accepts_a_matching_rs256_token() {
        let (jwt, jwks) = sample_jwt(
            1_700_000_000 + 600,
            "aud-tag",
            "https://team.cloudflareaccess.com",
        );
        let rules = AccessRules {
            issuer: "https://team.cloudflareaccess.com".into(),
            audience: "aud-tag".into(),
        };
        verify_access_jwt(&jwt, &jwks, &rules, 1_700_000_000).unwrap();
    }

    #[test]
    fn access_jwt_rejects_bad_signature_audience_and_expiry() {
        let (jwt, jwks) = sample_jwt(
            1_700_000_000 + 30,
            "aud-tag",
            "https://team.cloudflareaccess.com",
        );
        let rules = AccessRules {
            issuer: "https://team.cloudflareaccess.com".into(),
            audience: "aud-tag".into(),
        };
        let mut chars = jwt.chars().collect::<Vec<_>>();
        let last = chars.len() - 2;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(verify_access_jwt(&tampered, &jwks, &rules, 1_700_000_000)
            .unwrap_err()
            .contains("signature"));

        let wrong_aud = AccessRules {
            audience: "other".into(),
            ..rules.clone()
        };
        assert!(verify_access_jwt(&jwt, &jwks, &wrong_aud, 1_700_000_000)
            .unwrap_err()
            .contains("audience"));

        assert!(
            verify_access_jwt(&jwt, &jwks, &rules, 1_700_000_000 + 10_000)
                .unwrap_err()
                .contains("expired")
        );

        let none = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"test"}"#),
            URL_SAFE_NO_PAD.encode(
                br#"{"exp":1999999999,"iss":"https://team.cloudflareaccess.com","aud":"aud-tag"}"#
            )
        );
        assert!(verify_access_jwt(&format!("{none}."), &jwks, &rules, 1_700_000_000).is_err());
    }

    #[test]
    fn team_host_accepts_a_name_or_a_full_domain() {
        assert_eq!(
            team_host("example").unwrap(),
            "example.cloudflareaccess.com"
        );
        assert_eq!(
            team_host("https://example.cloudflareaccess.com/").unwrap(),
            "example.cloudflareaccess.com"
        );
    }

    fn sample_jwt(exp: u64, aud: &str, iss: &str) -> (String, String) {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT","kid":"test-key"}"#);
        let payload_json =
            serde_json::json!({ "exp": exp, "iss": iss, "aud": [aud], "sub": "svc" });
        let payload = URL_SAFE_NO_PAD.encode(payload_json.to_string().as_bytes());
        let input = format!("{header}.{payload}");
        let signing = SigningKey::<Sha256>::new(private);
        let sig = signing.sign_with_rng(&mut rng, input.as_bytes());
        let jwt = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        let jwk = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "kid": "test-key",
                "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            }]
        });
        (jwt, jwk.to_string())
    }
}
