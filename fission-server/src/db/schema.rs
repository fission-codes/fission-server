// @generated automatically by Diesel CLI.

diesel::table! {
    accounts (id) {
        id -> Int4,
        did -> Text,
        username -> Text,
        email -> Text,
        app_id -> Nullable<Int4>,
        inserted_at -> Timestamp,
        updated_at -> Timestamp,
        volume_id -> Nullable<Int4>,
    }
}

diesel::table! {
    apps (id) {
        id -> Int4,
        cid -> Nullable<Text>,
        inserted_at -> Timestamp,
        updated_at -> Timestamp,
        owner_id -> Int4,
        volume_id -> Nullable<Int4>,
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

diesel::table! {
    volumes (id) {
        id -> Int4,
        inserted_at -> Timestamp,
        updated_at -> Timestamp,
        cid -> Text,
    }
}

diesel::joinable!(accounts -> volumes (volume_id));
diesel::joinable!(apps -> volumes (volume_id));

diesel::allow_tables_to_appear_in_same_query!(accounts, apps, email_verifications, volumes,);
