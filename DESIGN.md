# Software Architecture and Usage Design Goals

The Fission Server is focused on providing and coordinating DID-based accounts and UCAN-based capabilities to different apps and systems.

## Usage

Use this as the main component for Fission hosted services. These are the ODD set of services, complimenting [ODD SDK](https://odd.dev). Developers are the primary audience, but also early adopters who want an ODD account / "Login with ODD".

Let people who want run a managed namespace of accounts run their own instance of the server. This is likely an app developer with one or more apps and a large user base, or someone that wants to brand "Login with Brand" and accompanying domain names and other settings.

We _may_ support multi-tenant in the future (hosting multiple "Login with Brand" experiences), but we'd rather see other people running instances first and/or have a clear desire for many of these.

## Features

* Management of attached WNFS storage, including updating `_dnslink` entries for every account.
* Direct DNS capabilities, set up other DNS providers as secondaries

## Terms & Definitions

### Verified Accounts

These are accounts in the server-managed namespace who have a verified email. They have a relationship with the entity running the server -- which might be for a business, an app, or a service provider. These accounts are responsible for their apps, app accounts, storage used, and so on. It uses a managed username that creates friendly subdomains within the server.

The two user types are 1) developers building apps, and 2) early adopters who would like to have their own _Login with Brand_ account. Both have a username under a default subdomain e.g. _boris.odd.name_.

### App Accounts

These are accounts that use the ODD SDK WebCrypto API, passkeys and/or WalletAuth blockchain accounts to generate DIDs automatically. The primary use case is for instant sign on progressive accounts. These accounts are the responsibility of the developer / app owner, who is charged for storage usage and other resources managed by the server. The developer (who has a Verified Account) has capabilities to view quotas for these accounts, and even delete misbehaving App Accounts.
