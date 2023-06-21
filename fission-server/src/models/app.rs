//! App model

use chrono::NaiveDateTime;
use diesel::prelude::*;

#[derive(Debug, Queryable)]
/// App model
pub struct App {
    /// Internal Database Identifier
    pub id: i32,
    /// Foreign key to the owner account
    pub owner_id: i32,

    /// Inserted at timestamp
    pub inserted_at: NaiveDateTime,
    /// Updated at timestamp
    pub updated_at: NaiveDateTime,

    /// CID of the app
    pub cid: String,
}
