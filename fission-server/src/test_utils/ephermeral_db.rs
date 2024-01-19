use anyhow::{anyhow, Context as _, Result};
use diesel::{Connection, PgConnection, RunQueryDsl};

pub fn create_ephermeral_db(database_url: &str, db_name: &str) -> Result<()> {
    let postgres_url = format!("{}/postgres", database_url);

    let conn = &mut PgConnection::establish(&postgres_url)?;

    diesel::sql_query(&format!("CREATE DATABASE {}", db_name))
        .execute(conn)
        .map_err(|e| anyhow!(e))
        .context(format!("Could not create database {}", db_name))?;

    Ok(())
}

pub fn destroy_ephermeral_db(database_url: &str, db_name: &str) -> Result<()> {
    let postgres_url = format!("{}/postgres", database_url);

    let conn = &mut PgConnection::establish(&postgres_url)
        .context("Cannot connect to postgres database.")?;

    let disconnect_users = format!(
        "SELECT pg_terminate_backend(pid)
         FROM pg_stat_activity
         WHERE datname = '{}';",
        db_name
    );

    diesel::sql_query(&disconnect_users).execute(conn)?;

    let query = diesel::sql_query(&format!("DROP DATABASE {}", db_name));

    query
        .execute(conn)
        .context(format!("Could not drop database {}", db_name))?;

    Ok(())
}
