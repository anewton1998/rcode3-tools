//! Example model + repository.
//!
//! This is the pattern consumers copy for their own tables: a `FromRow` model
//! plus free functions that take `&Db` and run **runtime** queries (no
//! compile-time `query!` macros, so no `DATABASE_URL` is needed to build).
//! Every function documents its error cases per the workspace convention.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::error::Result;
use crate::pool::Db;

/// A row in the `widgets` table.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Widget {
    /// Server-generated primary key.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Insertion timestamp (server clock).
    pub created_at: DateTime<Utc>,
}

/// Insert a new widget and return the persisted row.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on connection or
/// constraint failures.
pub async fn insert_widget(db: &Db, name: &str) -> Result<Widget> {
    let widget = sqlx::query_as::<_, Widget>(
        "INSERT INTO widgets (name) VALUES ($1) RETURNING id, name, created_at",
    )
    .bind(name)
    .fetch_one(db.pool())
    .await?;
    tracing::debug!(id = %widget.id, name = %widget.name, "inserted widget");
    Ok(widget)
}

/// Fetch a widget by id, or `None` if absent.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on connection failures.
pub async fn get_widget(db: &Db, id: Uuid) -> Result<Option<Widget>> {
    let widget =
        sqlx::query_as::<_, Widget>("SELECT id, name, created_at FROM widgets WHERE id = $1")
            .bind(id)
            .fetch_optional(db.pool())
            .await?;
    Ok(widget)
}

/// List all widgets, most recently created first.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on connection failures.
pub async fn list_widgets(db: &Db) -> Result<Vec<Widget>> {
    let widgets = sqlx::query_as::<_, Widget>(
        "SELECT id, name, created_at FROM widgets ORDER BY created_at DESC, id DESC",
    )
    .fetch_all(db.pool())
    .await?;
    Ok(widgets)
}

/// Count the rows in `widgets`.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on connection failures.
pub async fn count_widgets(db: &Db) -> Result<i64> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM widgets")
        .fetch_one(db.pool())
        .await?;
    Ok(count)
}
