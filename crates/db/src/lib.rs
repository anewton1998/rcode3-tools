//! Generic Postgres access layer for the rcode3-tools workspace.
//!
//! Built on sqlx with **runtime queries** (no compile-time `DATABASE_URL`
//! requirement) and rustls TLS. The [`Db`] handle wraps a cloneable `PgPool`
//! (cheap to share via axum `State`) and always applies migrations on connect.
//!
//! The [`widgets`] module is an example schema — copy its insert / query / list /
//! count pattern for your own tables.
//!
//! Modules:
//! - [`error`] — the [`DbError`](error::DbError) enum and [`Result`](error::Result) alias.
//! - [`config`] — [`DbConfig`](config::DbConfig) and env-var loading.
//! - [`pool`] — the [`Db`](pool::Db) handle (connect + migrate).
//! - [`widgets`] — example model + repository functions.
//!
//! # Example
//!
//! ```no_run
//! use db::{Db, widgets};
//!
//! # async fn run() -> db::error::Result<()> {
//! let db = Db::connect_from_env().await?;
//! let widget = widgets::insert_widget(&db, "sprocket").await?;
//! let found = widgets::get_widget(&db, widget.id).await?;
//! assert_eq!(found.unwrap().name, "sprocket");
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod error;
pub mod pool;
pub mod widgets;

pub use config::DbConfig;
pub use error::{DbError, Result};
pub use pool::Db;
