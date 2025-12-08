mod user;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub fullname: String,
    pub email: String,
    #[sqlx(default)]
    #[serde(skip)]
    pub password_hash: Option<String>,
    // created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    pub created_at: DateTime<Utc>,
    // updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    pub updated_at: DateTime<Utc>,
}
