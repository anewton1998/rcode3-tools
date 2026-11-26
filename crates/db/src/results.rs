//! RDAP result store (the `rdap_results` table).
//!
//! One row per queried IP address; the dequeue UPSERTs so this is the
//! latest-known state per address. The public surface uses `std::net::IpAddr`;
//! the `inet` column is bound/decoded through `ipnet::IpNet` internally (a bare
//! address becomes a host route, `/32` for v4 and `/128` for v6).
//!
//! The RDAP body is stored as `jsonb` (bound as text with a `::jsonb` cast, read
//! back as text via `response::text`) so this crate needs no `serde_json` in its
//! API.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sqlx::FromRow;

use crate::error::Result;
use crate::pool::Db;

/// A stored RDAP result (latest per address).
#[derive(Debug, Clone)]
pub struct RdapResult {
    /// The queried address.
    pub address: IpAddr,
    /// The RIR registry that served it.
    pub registry: String,
    /// The queue job that last wrote this row, if recorded.
    pub job_id: Option<i64>,
    /// The request URI the response came from, if known.
    pub request_url: Option<String>,
    /// The RDAP response body as JSON text.
    pub response: String,
    /// The advertised RFC 9877 geofeed URL, if any.
    pub geofeed_href: Option<String>,
    /// The downloaded geofeed bytes, if any.
    pub geofeed_csv: Option<Vec<u8>>,
    /// When this row was last written.
    pub queried_at: DateTime<Utc>,
}

/// Private decode row: `address` arrives as `IpNet` (the `inet` mapping) and is
/// narrowed to `IpAddr` in [`RdapResult`].
#[derive(Debug, FromRow)]
struct RdapRow {
    address: IpNet,
    registry: String,
    job_id: Option<i64>,
    request_url: Option<String>,
    response: String,
    geofeed_href: Option<String>,
    geofeed_csv: Option<Vec<u8>>,
    queried_at: DateTime<Utc>,
}

impl RdapRow {
    fn into_result(self) -> RdapResult {
        RdapResult {
            address: self.address.network(),
            registry: self.registry,
            job_id: self.job_id,
            request_url: self.request_url,
            response: self.response,
            geofeed_href: self.geofeed_href,
            geofeed_csv: self.geofeed_csv,
            queried_at: self.queried_at,
        }
    }
}

/// Insert or update the result for `address` (latest wins).
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure
/// (e.g. `response_json` not being valid JSON for the `jsonb` column).
#[allow(clippy::too_many_arguments)]
pub async fn upsert_rdap_result(
    db: &Db,
    address: IpAddr,
    registry: &str,
    job_id: Option<i64>,
    request_url: Option<&str>,
    response_json: &str,
    geofeed_href: Option<&str>,
    geofeed_csv: Option<&[u8]>,
) -> Result<()> {
    let addr = IpNet::from(address);
    sqlx::query(
        "INSERT INTO rdap_results
             (address, registry, job_id, request_url, response, geofeed_href, geofeed_csv)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
         ON CONFLICT (address) DO UPDATE SET
             registry     = EXCLUDED.registry,
             job_id       = EXCLUDED.job_id,
             request_url  = EXCLUDED.request_url,
             response     = EXCLUDED.response,
             geofeed_href = EXCLUDED.geofeed_href,
             geofeed_csv  = EXCLUDED.geofeed_csv,
             queried_at   = now()",
    )
    .bind(addr)
    .bind(registry)
    .bind(job_id)
    .bind(request_url)
    .bind(response_json)
    .bind(geofeed_href)
    .bind(geofeed_csv)
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Fetch the stored result for `address`, if present.
///
/// # Errors
///
/// Returns [`DbError::Sql`](crate::error::DbError::Sql) on a database failure.
pub async fn get_rdap_result(db: &Db, address: IpAddr) -> Result<Option<RdapResult>> {
    let addr = IpNet::from(address);
    let row = sqlx::query_as::<_, RdapRow>(
        "SELECT address, registry, job_id, request_url, response::text AS response,
                geofeed_href, geofeed_csv, queried_at
         FROM rdap_results WHERE address = $1",
    )
    .bind(addr)
    .fetch_optional(db.pool())
    .await?;
    Ok(row.map(RdapRow::into_result))
}
