mod config;
mod error;
mod handlers;
mod models;
mod utils;

use anyhow::Context;
use handlers::*;
use sqlx::PgPool;
#[cfg(test)]
use sqlx_db_tester::TestPg;
use std::{fmt, ops::Deref, sync::Arc};

use axum::{
    Router,
    routing::{get, patch, post},
};

pub use config::AppConfig;
pub use error::{AppError, ErrorOutput};
pub use models::User;

use crate::utils::{DecodingKey, EncodingKey};

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    inner: Arc<AppStateInner>,
}

#[allow(unused)]
pub(crate) struct AppStateInner {
    pub(crate) config: AppConfig,
    pub(crate) ek: EncodingKey,
    pub(crate) dk: DecodingKey,
    pub(crate) pool: PgPool,
}

pub async fn get_router(config: AppConfig) -> Result<Router, AppError> {
    let state = AppState::try_new(config).await?;

    let api = Router::new()
        .route("/signin", post(signin_handler))
        .route("/signup", post(signup_handler))
        .route("/chat", get(list_chat_handler).post(create_chat_handler))
        .route(
            "/chat/{id}",
            patch(update_chat_handler)
                .delete(delete_chat_handler)
                .post(send_message_handler),
        )
        .route("/chat/{id}/messages", get(list_message_handler));

    let app = Router::new().route("/", get(index_handler)).nest("/api", api).with_state(state);
    Ok(app)
}

// 当我调用 state.config => state.inner.config
impl Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AppState {
    // #[cfg(not(test))]
    pub async fn try_new(config: AppConfig) -> Result<Self, AppError> {
        let dk = DecodingKey::load(&config.auth.pk).context("Failed to load public key")?;
        let ek = EncodingKey::load(&config.auth.sk).context("Failed to load private key")?;
        let pool = PgPool::connect(&config.server.db_url)
            .await
            .context("Failed to connect to database")?;

        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
                ek,
                dk,
                pool,
            }),
        })
    }
}

impl fmt::Debug for AppStateInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppStateInner").field("config", &self.config).finish()
    }
}

#[cfg(test)]
impl AppState {
    pub async fn new_for_test(config: AppConfig) -> Result<(TestPg, Self), AppError> {
        let dk = DecodingKey::load(&config.auth.pk).context("Failed to load public key")?;
        let ek = EncodingKey::load(&config.auth.sk).context("Failed to load private key")?;

        let post = config.server.db_url.rfind('/').expect("invalid db_url");
        let server_url = &config.server.db_url[..post];
        println!("server_url: {}", server_url);
        let tdb = TestPg::new(
            server_url.to_string(),
            std::path::Path::new("../migrations"),
        );

        let pool = tdb.get_pool().await;
        let state = Self {
            inner: Arc::new(AppStateInner {
                config,
                ek,
                dk,
                pool,
            }),
        };
        Ok((tdb, state))
    }
}
