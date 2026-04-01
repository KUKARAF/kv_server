use anyhow::Result;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::str::FromStr;

pub async fn create_pool(database_url: &str) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(database_url)?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(16)
        .connect_with(opts)
        .await?;

    Ok(pool)
}
