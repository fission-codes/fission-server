# Dictionary

| Term               | Summary    |
|--------------------|------------|
| [App]              |            |
| [Account]          |            |
| [App Account]      |            |
| [Verified Account] |            |
| [Volume]           |            |

# App

* Owned by _one_ Fission user
  * Extend permissions to others via UCAN
* Gets a `fission.app` subdomain
* Storage points at a path inside the owner's Volume

# Account

## Verified Account

These are accounts in the server-managed namespace who have a verified email. They have a relationship with the entity running the server -- which might be for a business, an app, or a service provider. These accounts are responsible for their apps, app accounts, storage used, and so on. It uses a managed username that creates friendly subdomains within the server.

The two user types are 1) developers building apps, and 2) early adopters who would like to have their own _Login with Brand_ account. Both have a username under a default subdomain e.g. _boris.odd.name_.

## App Account

While we could arguably roll these into Fission users, the requirements are different enough in this revision that splitting them out makes sense.

* Get a DNS subdomain at `<username>.<appname>.<domain>`
    * Where the default `<domain>` is `fission.app`
* Get assigned a Volume

Unlike Fission users, we don't need to capture their email address or other info (we may later, but not for now).

These are accounts that use the ODD SDK WebCrypto API, passkeys and/or WalletAuth blockchain accounts to generate DIDs automatically. The primary use case is for instant sign on progressive accounts. These accounts are the responsibility of the developer / app owner, who is charged for storage usage and other resources managed by the server. The developer (who has a Verified Account) has capabilities to view quotas for these accounts, and even delete misbehaving App Accounts.



<!-- Internal Links -->

[App Account]: #app-account
[Verified Account]: #verified-account
