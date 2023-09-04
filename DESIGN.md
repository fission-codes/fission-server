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

## Technical Design

### Routes

Verified & App accounts:
- `POST /api/v1/account` body: `{ did: string, username: string } & ({ email: string } | { app: string })`, creates an account, optionally associates an email or app with the account.
- `GET /api/v1/account/username/{username}` -> `{ did: string, username: string, email?: string, app?: string, apps: string[] }`, needs full capabilities rooted in the server
- `GET /api/v1/account/did/{did}` -> same as above
- `PUT /api/v1/account/{did}/did` body: DID, needs auth UCAN that got sent via E-Mail, sets the account to verified
- `DELETE /api/v1/account/{did}`

Apps:
- `POST /api/v1/apps/` body: `{ did: string, app: string }`, creates an app at a verified user's account. Needs UCAN rooted in a verified user's DID. Fails if used by a "scoped" user.
- `GET /api/v1/apps/{did}`, returns the list of registered apps for a verified user.
- `DELETE /api/v1/apps/{did}`

Volumes:
- `PUT /api/v1/volume/{did}/{cid}` body according to CAR-mirror. Sets the volume for given user (by their DID) to given CID. Needs two capabilities: One for updating the WNFS, rooted in the DID in the root block, and a capability for the account, rooted in the server's DID.
- `GET /api/v1/car-mirror/{cid}` fetch something via car-mirror & CID.
- Latest CID for a DID can be fetched via DNS.

### DNS

Each account has two dns entries:
1. An entry for their DID.
2. An entry for their volume CID.

Both entries are keyed by
- The username if the account has a verified email address, so e.g. `_did.alice.fission.name` and `_dnslink.alice.fission.name`
- The username *and app* if the account is associated to an app, so e.g. `_did.alice.flatawesome.fission.name` and `_dnslink.alice.flatawesome.fission.name`
- As a fallback, the hash of their DID `_did.ca38e77764c7d164ca38e77764c7d164.hashed.fission.name` (although each account should be either associated with an app or be verified).

### Data Invariants

Should usernames be unique, even across apps? This may make "moving" your account from namespace'd to verified easier in the future.

Should we key volumes by their root DID? This would enable having multiple volumes eventually. It would also mean we're tracking the DID in a DB, giving us easy search by root WNFS DID in the future.

Should emails be unique?

Should we allow changing the DID of a volume? This may be needed for recovery. This should only be allowed when you have root access to the volume.

### UCAN Rooting

For quotas/limits & account management:

Options:
1. Single server DID. Could be `did:web:runfission.com` or a single root DID. Perhaps rotate the key every now and then + update clients to newer DIDs automatically?
2. Offline server DID. Every account gets an ephermeral keypair. These keypairs delegate `ucan:*` to an offline keypair. That keypair needs to have the right to revoke. Not sure how that offline key gets rotated.

I'm leaning towards option (1). This will give us following setup in a "full" version *eventually*:
- Have multiple keys active at the same time, keyed by a date, e.g. sign account UCANs as `did:web:fission.codes#2023-09-01`
- Keep only the private key for the most recent key. (Rotate let's say, every month)
- Each time we rotate, remove any keys that are older than 6 months.
- Everytime we get a request that's rooted in one of our older keys (up to 6 months old), we allow the request, but answer with a code indicating that users can take that UCAN and upgrade it to a more recent key. (Maybe for a first version we allow *any* old key, unless we know it has been compromised?)

For WNFS: Rooted in DIDs that are local to the user. E.g. passkeys, wallet keys or WebCrypto keys.

### UCAN Capabilities

TODO
