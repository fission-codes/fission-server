# Fission Server API Specification

## Abstract

This spec describes
- available [server routes](#routes) and which [UCAN] capabilities the these routes expect
- the [set of capabilities](#ucan-capabilities) the server understands and how they can imply each other.


## Routes

Today we use a REST API. In the future we may switch to an RPC-based design. When/if this happens mostly depends on a plan for implementing the UCAN invocation spec.

| Method | Path | Comment |
|--------|------|---------|
| POST | [`/api/v0/auth/email/verify`](#post-apiv0authemailverify) | Trigger email verification |
| POST | [`/api/v0/account`](#post-apiv0account) | Create a full account |
| GET | [`/api/v0/account/:did`](#get-apiv0accountdid) | Get account information by DID |
| GET | [`/api/v0/account/:username/did`](#get-apiv0accountusernamedid) | Get the did of an account by username |
| PUT | [`/api/v0/account/:did/username/:username`](#put-apiv0accountdidusernameusername) | Change an account's username |
| GET | [`/api/v0/capabilities`](#get-apiv0capabilities) | Get capabilities for a given account |

A note on authorization:

For all UCANs that are sent to the server for authorization, following things must hold:
- All capability resources need to be DID URIs.
- A UCAN with a resource DID that's not equal to its issuer DID needs a valid proof chain to a UCAN where this condition holds.
- The final link in the UCAN chain needs to have the server DID as the audience.

These conditions won't be repeated in the route-specific authorization sections.

### POST `/api/v0/auth/email/verify`

---

**Authorization**: Unauthorized

**Request**:

| Field | Type | Comment |
|-------|------|---------|
| `email` | `string` | The email to send the verification code to |

**Response**:

| Field | Type | Comment |
|-------|------|---------|
| `success` | `bool` | True if sending the email was successful |

---

- Sends an email with a 6-digit verification code to given address
- A hash of the code and email address is stored in a database
- The code expires after 24 hours
- Codes will be deleted when used


### POST `/api/v0/account`

---

**Authorization**: UCAN with ability `account/create`. The resource DID will be the audience for returned UCANs.

**Request**:

| Field | Type | Comment |
|-------|------|---------|
| `code` | `number` | The code from the verification email |
| `email` | `string` | |
| `username` | `string` | |
| `credentialID` | `string` | Optional. If present, this may be useful for better passkey UX. |

This info is passed in the UCAN facts field.

**Response**:

| Field | Type | Comment |
|-------|------|---------|
| `ucans` | `Array<string>` | A set of UCAN delegations that delegate the account's unique DID to the resource DID from the request authorization. |

---

This request registers a full account given an email verification code and delegates the account's access to given DID. In the future more UCANs may be involved in the delgation chain in the response.


### GET `/api/v0/account/:did`

---

**Authorization**: UCAN giving access to the ability `account/info` with the account's DID as resource.

**Request**: Two optional query parameters: `?resource=<resource did>&ability=<ability>` to filter/look for specific resources or abilities.

**Response**:

| Field      | Type     |
|------------|----------|
| `email`    | `string` |
| `did`      | `string` |
| `username` | `string` |

---

This fetches the latest account information.

### GET `/api/v0/account/:username/did`

---

**Authorization**: *Unauthenticated*

**Response**:

| Field | Type     |
|-------|----------|
| `did` | `string` |

---

Use this to find out an account's DID. This information may be substituted by DoH & a DNS record in the future.


### PUT `/api/v0/account/:did/username/:username`

---

**Authorization**: UCAN with ability `account/manage`.

**Response**:

Status 200 OK and `{ success: true }`, if successful.

Status 409 Conflict and `{ success: false }`, if the username is already taken.

---

Change the account's username.


### GET `/api/v0/capabilities`

---

**Authorization**: UCAN with ability `capability/find`.

**Response**:

| Field | Type | Comment |
|-------|------|---------|
| `ucans` | `Array<string>` | A set of ucans giving the DID from the resource in the authorization capabilities. |

---

This returns the set of UCANs in UCAN chains that have the authorization UCAN's resource DID as final audience.

This way agents can discover new capabilities, or make use of the server as persistent storage for their UCANs, e.g. when their storage gets wiped, but they manage to keep or recover their DID.

In some cases this can be useful for logging in a new devices. E.g. when passkeys are available and are synced between devices, e.g. it's easy to ask a synced passkey to sign a UCAN giving the `"ucan:*": { "*": [{}] }` capability. However, this UCAN on its own doesn't give the account access to anything yet. It can use this endpoint to fetch the `"did:key:<account>": { "*": [{}] }` capability UCANs that delegate to the passkey.

In the future this endpoint will be useful for fetching new capabilities from other services that were delegated to a user's account.


## UCAN Capabilities

### Resources

Anticipating the upcoming changes to the UCAN spec, where each capability is associated with a "subject" that's *always a DID*, resources for the fission server are also always DIDs.

Examples:
- `did:key:z6Mkw5d3acoQqn97UjRcGit7J7uWunixxxDKTgkr58CFHLfo`
- `did:key:z6Mkh5xiFmvPkWeHYZYnBLS4jVjsCjtpBS7D4thq1stdyEBK`

Often, these DIDs represent an identifier that is unique for every account and after delegating rights to the main server DID, the associated private key is deleted.

Sometimes, these DIDs are generated by clients and represent one of their devices.

### Abilities

```mermaid
flowchart TD
    Star["account/*"] --> Noncrit["account/noncritical"]
    Noncrit --> Info["account/info"]
    Star --> Manage["account/manage"]
    Star --> Delete["account/delete"]
    CapFind["capability/find"]
```

#### `account/noncritical` & `account/*`

Account abilities on the fission server are grouped into two categories: critical and non-critical.

This destinction allows delegating only non-critical capabilities to a user session, while requiring e.g. a second factor/biometrics for access to any critical capabilities.

This distinction is represented by the `account/noncritical` ability, which subsumes all non-critical capabilities. To delegate access to all capabilities, including criticial capabilities, use `account/*`.

#### `account/create`

Critical. Allows associating the originator of this capability on a newly created account.

#### `account/info`

Non-critical. Allows fetching the associated username/email address or similar information about an account.

#### `account/manage`

Critical. Allows changing the username.

#### `account/delete`

Critical. Allows deleting an account.

#### `capability/find`

Allows finding UCANs known to the server to give capabilities to the associated resource DID.


[UCAN]: https://github.com/ucan-wg
[design document]: ./README.md
