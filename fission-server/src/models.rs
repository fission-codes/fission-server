//! Structs

#![allow(missing_docs)]

use chrono::NaiveDateTime;
use diesel::prelude::*;

#[derive(Debug, Queryable)]
/// Account model
pub struct Account {
    pub id: i32,
    pub app_id: i32,

    pub inserted_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub did: String,
    pub email: String,
    pub username: String,
}

#[derive(Debug, Queryable)]
/// App model
pub struct App {
    pub id: i32,
    pub owner_id: i32,

    pub inserted_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub cid: String,
}
