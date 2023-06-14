use chrono::NaiveDateTime;
use diesel::prelude::*;

#[derive(Debug, Queryable)]
/// App model
pub struct App {
    pub id: i32,
    pub cid: Option<String>,

    pub inserted_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub owner_id: i32,
}
