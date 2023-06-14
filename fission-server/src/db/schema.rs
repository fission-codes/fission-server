// @generated automatically by Diesel CLI.

diesel::table! {
    accounts (id) {
        id -> Int4,
        did -> Text,
        username -> Text,
        email -> Text,
        app_id -> Int4,
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

diesel::table! {
    email_verifications (id) {
        id -> Int4,
        inserted_at -> Timestamp,
        updated_at -> Timestamp,
        email -> Text,
        did -> Text,
        code_hash -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(accounts, apps, email_verifications,);
