use aws_lambda_events::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequest,
    ApiGatewayCustomAuthorizerResponse, IamPolicyStatement,
};
use claims::dump_claims;
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::Client;
use tokio::io::AsyncReadExt;
use anyhow::Result;

use log::{info};

use crate::claims::{get_group};

mod claims;

pub async fn read_s3_json(
    bucket: String,
    key: String,
) -> Result<Vec<IamPolicyStatement>, anyhow::Error> {
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let config = aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&config);

    let mut data = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await?
        .body
        .into_async_read();

    let mut buf: Vec<u8> = Vec::new();

    data.read_to_end(&mut buf).await.expect("could not read stream");

    let s3_data: Result<Vec<IamPolicyStatement>, anyhow::Error> = serde_json::from_slice(&buf).map_err(|e| anyhow::anyhow!("{}", e));
    s3_data
}

async fn get_policy(ctx: serde_json::Value, group: String) -> ApiGatewayCustomAuthorizerResponse {
    let bucket: std::string::String = std::env::var("S3_BUCKET").unwrap();
    let key = format!("{}.json", group);
    info!("s3 key: {:?}", key);
    let policy = read_s3_json(bucket, key).await;
    let policy_json = policy.unwrap();
    info!("policy: {:?}", policy_json);
    ApiGatewayCustomAuthorizerResponse {
        principal_id: None,
        policy_document: ApiGatewayCustomAuthorizerPolicy {
            version: Some("2012-10-17".to_owned()),
            statement: policy_json,
        },
        usage_identifier_key: None,
        context: ctx,
    }
}

async fn function_handler(
    client_id: &str,
    keyset: &jsonwebtokens_cognito::KeySet,
    event: LambdaEvent<ApiGatewayCustomAuthorizerRequest>,
) -> Result<ApiGatewayCustomAuthorizerResponse, claims::AuthorizerError> {
    let mut ctx = serde_json::Value::default();
    let mut group = "".to_string();

    info!("token:{}", event.payload.authorization_token.clone().unwrap());
    info!("method_arn:{}", event.payload.method_arn.unwrap());
    let verifier = keyset.new_access_token_verifier(&[client_id]).build()?;
    let token_full = event.payload.authorization_token.unwrap();
    let token = token_full.replace("Bearer ", "");
    let claims: Result<serde_json::Value, jsonwebtokens_cognito::Error> =
        keyset.try_verify(token.as_str(), &verifier);

    match claims {
        Ok(d) => {
            ctx = dump_claims(&d)?;
            group = get_group(&d).unwrap_or_else(|_e| {
                "none".to_string()
            });
        },
        Err(_) => {"Deny";}
    }

    let response = get_policy(ctx, group);
    Ok(response.await)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .init();

    let region_id: String = std::env::var("REGION_ID").unwrap();
    let user_pool_id: String = std::env::var("USER_POOL_ID").unwrap();
    let client_id = &std::env::var("CLIENT_ID").expect("CLIENT_ID must be set");
    let keyset = jsonwebtokens_cognito::KeySet::new(region_id, user_pool_id).unwrap();
    let _ = keyset.prefetch_jwks().await;
    let shared_keyset = &keyset;

    run(service_fn(
        move |event: LambdaEvent<ApiGatewayCustomAuthorizerRequest>| async move {
            function_handler(client_id, &shared_keyset, event).await
        },
    ))
    .await
}