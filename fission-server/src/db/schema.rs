// @generated automatically by Diesel CLI.

diesel::table! {
    accounts (id) {
        id -> Int4,
        did -> Text,
        username -> Nullable<Text>,
        email -> Nullable<Text>,
        inserted_at -> Timestamp,
        updated_at -> Timestamp,
        volume_id -> Nullable<Int4>,
        handle -> Nullable<Text>,
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
    capabilities (id) {
        id -> Int4,
        resource -> Text,
        ability -> Text,
        caveats -> Jsonb,
        ucan_id -> Int4,
    }
}

diesel::table! {
    email_verifications (id) {
        id -> Int4,
        inserted_at -> Timestamp,
        updated_at -> Timestamp,
        email -> Text,
        code -> Text,
    }
}

diesel::table! {
    revocations (id) {
        id -> Int4,
        cid -> Text,
        iss -> Text,
        challenge -> Text,
    }
}

diesel::table! {
    ucans (id) {
        id -> Int4,
        cid -> Text,
        encoded -> Text,
        issuer -> Text,
        audience -> Text,
        not_before -> Nullable<Timestamp>,
        expires_at -> Nullable<Timestamp>,
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
diesel::joinable!(apps -> accounts (owner_id));
diesel::joinable!(apps -> volumes (volume_id));
diesel::joinable!(capabilities -> ucans (ucan_id));

diesel::allow_tables_to_appear_in_same_query!(
    accounts,
    apps,
    capabilities,
    email_verifications,
    revocations,
    ucans,
    volumes,
);
