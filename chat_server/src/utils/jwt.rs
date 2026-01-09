use jwt_simple::prelude::*;

use crate::{AppError, User};

const JWT_DURATION: u64 = 60 * 60 * 24 * 7;
const JWT_ISSUER: &str = "chat_server";
const JWT_AUDIENCE: &str = "chat_web";

pub struct EncodingKey(Ed25519KeyPair);
#[allow(unused)]
pub struct DecodingKey(Ed25519PublicKey);

impl EncodingKey {
    pub fn load(pem: &str) -> Result<Self, AppError> {
        Ok(Self(Ed25519KeyPair::from_pem(pem)?))
    }

    pub fn sign(&self, user: impl Into<User>) -> Result<String, AppError> {
        let claims = Claims::with_custom_claims(user.into(), Duration::from_secs(JWT_DURATION))
            .with_issuer(JWT_ISSUER)
            .with_audience(JWT_AUDIENCE);
        Ok(self.0.sign(claims)?)
    }
}

impl DecodingKey {
    pub fn load(pem: &str) -> Result<Self, AppError> {
        Ok(Self(Ed25519PublicKey::from_pem(pem)?))
    }

    #[allow(unused)]
    pub fn verify(&self, token: &str) -> Result<User, AppError> {
        // let mut options = VerificationOptions::default();
        // options.allowed_issuers = Some(HashSet::from_strings(&[JWT_ISSUER]));
        // options.allowed_audiences = Some(HashSet::from_strings(&[JWT_AUDIENCE]));

        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from_strings(&[JWT_ISSUER])),
            allowed_audiences: Some(HashSet::from_strings(&[JWT_AUDIENCE])),
            ..Default::default()
        };

        let claims = self.0.verify_token::<User>(token, Some(options))?;
        Ok(claims.custom)
    }
}

// pub fn generate_token(user: User, key: &EncodingKey) -> Result<String, AppError> {
//     let claims = Claims::with_custom_claims(user, Duration::from_secs(JWT_DURATION));
//     Ok(key.sign(claims)?)
// }

// impl Deref for EncodingKey {
//     type Target = Ed25519KeyPair;
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

// impl Deref for DecodingKey {
//     type Target = Ed25519PublicKey;
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn jwt_sign_verify_should_work() -> Result<()> {
        let encoding_key = include_str!("../../fixtures/encoding.pem");
        let decoding_key = include_str!("../../fixtures/decoding.pem");

        let encoding_key = EncodingKey::load(encoding_key)?;
        let decoding_key = DecodingKey::load(decoding_key)?;

        let user = User::new(1, "Paxon Qiao", "paxon@acme.org");
        let token = encoding_key.sign(user)?;
        assert_eq!(token.len(), 432);
        assert!(token.starts_with("eyJ"));
        assert!(token.contains("."));

        let user = decoding_key.verify(&token)?;
        assert_eq!(user.id, 1);
        assert_eq!(user.fullname, "Paxon Qiao");
        assert_eq!(user.email, "paxon@acme.org");

        let token = encoding_key.sign(user.clone())?;
        let user2 = decoding_key.verify(&token)?;
        assert_eq!(user, user2);

        Ok(())
    }
}
