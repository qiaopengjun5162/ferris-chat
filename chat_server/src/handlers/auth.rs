use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::{
    AppError, AppState, ErrorOutput, User,
    models::{CreateUser, SigninUser},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthOutput {
    token: String,
}

pub(crate) async fn signup_handler(
    State(state): State<AppState>,
    Json(input): Json<CreateUser>,
) -> Result<impl IntoResponse, AppError> {
    let user = User::create(&input, &state.pool).await?;
    let token = state.ek.sign(user)?;

    let mut headers = HeaderMap::new();
    headers.insert("X-Token", HeaderValue::from_str(&token)?);

    Ok((StatusCode::CREATED, headers, Json(AuthOutput { token })))
}

pub(crate) async fn signin_handler(
    State(state): State<AppState>,
    Json(input): Json<SigninUser>,
) -> Result<impl IntoResponse, AppError> {
    let user = User::verify(&input, &state.pool).await?;

    match user {
        Some(user) => {
            let token = state.ek.sign(user)?;
            Ok((StatusCode::OK, Json(AuthOutput { token })).into_response())
        }
        // None => Ok((StatusCode::FORBIDDEN, "Invalid email or password").into_response()),
        None => {
            let body = Json(ErrorOutput::new("Invalid email or password"));
            Ok((StatusCode::FORBIDDEN, body).into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::AppConfig;

    use super::*;
    use anyhow::Result;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn signup_should_work() -> Result<()> {
        let config = AppConfig::load()?;
        let (_tdb, state) = AppState::new_for_test(config).await?;
        let input = CreateUser::new("Paxon Qiao", "paxonqiao@acme.org", "qiao123456");
        let ret = signup_handler(State(state), Json(input)).await?.into_response();
        assert_eq!(ret.status(), StatusCode::CREATED);
        let body = ret.into_body().collect().await?.to_bytes();
        let ret: AuthOutput = serde_json::from_slice(&body)?;
        let token = ret.token;
        assert!(!token.is_empty());
        // assert!(token.len() > 0);
        assert!(token.contains("."));
        assert_eq!(token.split(".").count(), 3);
        assert!(token.starts_with("eyJ"));
        Ok(())
    }

    #[tokio::test]
    async fn signup_duplicate_user_should_409() -> Result<()> {
        let config = AppConfig::load()?;
        let (_tdb, state) = AppState::new_for_test(config).await?;
        let input = CreateUser::new("Paxon Qiao", "paxonqiao@acme.org", "qiao123456");
        signup_handler(State(state.clone()), Json(input.clone())).await?;
        let ret = signup_handler(State(state.clone()), Json(input.clone())).await.into_response();
        assert_eq!(ret.status(), StatusCode::CONFLICT);
        let body = ret.into_body().collect().await?.to_bytes();
        // let ret: serde_json::Value = serde_json::from_slice(&body)?;
        let ret: ErrorOutput = serde_json::from_slice(&body)?;
        // let msg = ret.get("error").unwrap().as_str().unwrap();
        // assert_eq!(msg, "email already exists: paxonqiao@acme.org");
        assert_eq!(ret.error, "email already exists: paxonqiao@acme.org");

        Ok(())
    }

    #[tokio::test]
    async fn signin_should_work() -> Result<()> {
        let config = AppConfig::load()?;
        let (_tdb, state) = AppState::new_for_test(config).await?;
        let name = "Alice";
        let email = "alice@example.com";
        let password = "alice123";
        let user = CreateUser::new(name, email, password);
        User::create(&user, &state.pool).await?;
        let input = SigninUser::new(email, password);
        let ret = signin_handler(State(state), Json(input)).await?.into_response();
        assert_eq!(ret.status(), StatusCode::OK);
        let body = ret.into_body().collect().await?.to_bytes();
        let ret: AuthOutput = serde_json::from_slice(&body)?;
        assert_ne!(ret.token, "");
        assert!(ret.token.len() > 10);
        assert!(ret.token.contains("."));
        assert_eq!(ret.token.split(".").count(), 3);
        assert!(ret.token.starts_with("eyJ"));
        Ok(())
    }

    #[tokio::test]
    async fn signin_with_non_exist_user_should_403() -> Result<()> {
        let config = AppConfig::load()?;
        let (_tdb, state) = AppState::new_for_test(config).await?;

        let email = "alice@example.com";
        let password = "alice123";

        let input = SigninUser::new(email, password);
        let ret = signin_handler(State(state), Json(input)).await.into_response();
        assert_eq!(ret.status(), StatusCode::FORBIDDEN);
        let body = ret.into_body().collect().await?.to_bytes();
        let ret: ErrorOutput = serde_json::from_slice(&body)?;
        assert_eq!(ret.error, "Invalid email or password");
        Ok(())
    }
}
