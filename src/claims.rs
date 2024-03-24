use serde::{de::value::StringDeserializer, Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthorizerError {
    #[error("Something is wrong with the Cognito portion of the JWT")]
    JWTCognitoError,
    #[error("The JSON was bad.  The serde failed.")]
    InvalidSerde,
    #[error("The JWT is invalid")]
    InvalidJWT,
}

impl From<jsonwebtokens::error::Error> for AuthorizerError {
    fn from(_: jsonwebtokens::error::Error) -> Self {
        AuthorizerError::InvalidJWT
    }
}

impl From<serde_json::Error> for AuthorizerError {
    fn from(_: serde_json::Error) -> Self {
        AuthorizerError::InvalidSerde
    }
}

impl From<jsonwebtokens_cognito::Error> for AuthorizerError {
    fn from(_: jsonwebtokens_cognito::Error) -> Self {
        AuthorizerError::JWTCognitoError
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    pub sub: String,
    #[serde(rename = "device_key")]
    pub device_key: String,
    #[serde(rename = "cognito:groups")]
    pub cognito_groups: Vec<String>,
    pub iss: String,
    #[serde(rename = "client_id")]
    pub client_id: String,
    #[serde(rename = "origin_jti")]
    pub origin_jti: String,
    #[serde(rename = "event_id")]
    pub event_id: String,
    #[serde(rename = "token_use")]
    pub token_use: String,
    pub scope: String,
    #[serde(rename = "auth_time")]
    pub auth_time: i64,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PrivateClaim {
    user_name: String,
    device_key: String
}

pub fn dump_claims(value: &serde_json::Value) -> Result<serde_json::Value, serde_json::Error> {
    let claim: Result<Claim, serde_json::Error> = serde_json::from_value(value.clone());
    tracing::debug!("(Claim_JSON): {}", value);
    tracing::debug!("(Claim_Struct): {:?}", claim);

    match claim {
        Ok(c) => {
            let pc = PrivateClaim {
                user_name: c.username,
                device_key: c.device_key
            };
            tracing::debug!("(PrivateClaim): {:?}", pc);
            let pc_v = serde_json::to_value(pc)?;
            Ok(pc_v)
        }
        Err(e) => {
            tracing::error!("(Claim_Struct): {:?}", e);
            Err(e)
        }
    }
}

pub fn get_group(value: &serde_json::Value) -> Result<String, anyhow::Error> {
    let claim: Result<Claim, serde_json::Error> = serde_json::from_value(value.clone());
    tracing::debug!("(Claim_JSON): {}", value);
    tracing::debug!("(Claim_Struct): {:?}", claim);

    match claim {
        Ok(c) => {
            let group: Option<&str> = c.cognito_groups.first().map(|s| s.as_str());
            let key_first: Option<String> = group.map(|s| s.to_string());
            let key = key_first.as_ref().unwrap().to_string().to_lowercase();
            
            Ok(key)
        }
        Err(e) => {
            tracing::error!("(Claim_Struct): {:?}", e);
            Err(e).map_err(|e| anyhow::anyhow!("{}", e))
        }
    }
}