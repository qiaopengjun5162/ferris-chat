use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorOutput {
    pub error: String,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("email already exists: {0}")]
    EmailAlreadyExists(String),

    #[error("SQLx error: {0}")]
    SqlxError(#[from] sqlx::Error),

    #[error("Password hash error: {0}")]
    PasswordHashError(#[from] argon2::password_hash::Error),

    #[error("JWT error: {0}")]
    JWTError(#[from] jwt_simple::Error),

    #[error("http header parse  error:  {0}")]
    HttpHeaderParseError(#[from] axum::http::header::InvalidHeaderValue),
}

impl ErrorOutput {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response<axum::body::Body> {
        let status = match &self {
            Self::EmailAlreadyExists(_) => StatusCode::CONFLICT,
            Self::SqlxError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::PasswordHashError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::JWTError(_) => StatusCode::FORBIDDEN,
            Self::HttpHeaderParseError(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        // (status, Json(json!({"error": self.to_string()}))).into_response()
        (status, Json(ErrorOutput::new(self.to_string()))).into_response()
    }
}
