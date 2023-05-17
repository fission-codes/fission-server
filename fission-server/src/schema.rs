// @generated automatically by Diesel CLI.

#![allow(missing_docs)]

diesel::table! {
    accounts (id) {
        id -> Int4,
        did -> Text,
        username -> Text,
        verified -> Bool,
        email -> Text,
        app_id -> Nullable<Int4>,
        inserted_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    apps (id) {
        id -> Int4,
        cid -> Nullable<Text>,
        inserted_at -> Timestamp,
        updated_at -> Timestamp,
        owner_id -> Int4,
    }
}

diesel::allow_tables_to_appear_in_same_query!(accounts, apps,);
