# Safenet Protocol Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Authors:** Qbix, Inc.
**Date:** 2026-10-07

---

## 1. Overview

Safenet is a trust network protocol for Safebox-to-Safebox communication, distributed package management, and payment settlement. It provides:

1. **Mutual attestation** — Safeboxes verify each other's integrity before exchanging sensitive material.
2. **Distributed package registry** — A decentralized alternative to centralized registries (npm, Packagist, etc.), where package metadata is replicated across attested Safeboxes using content-addressed data structures.
3. **Secure publication** — Authors publish software via standard git/hg pushes, with OCP-signed manifests and optional second-factor authentication.
4. **Payment settlement** — Safebux micropayments for proprietary software licenses, settled off-chain with optional on-chain redemption via the OpenClaiming EVM Payments contract.
5. **Revocation and transparency** — Append-only logs and gossip-propagated revocations for keys, packages, and namespaces.

Safenet builds on three foundations:

- **OpenClaiming Protocol (OCP)** — The wire format for all signed claims (`{ocp:1, iss, sub, stm, key:[], sig:[]}`). Supports ES256 (P-256) and EIP-712 (secp256k1) signing schemes with M-of-N multisignature.
- **Q.Crypto** — Typed-message signing, deterministic keypair derivation (HKDF), and delegation ceremonies.
- **Q.Data** — RFC 8785 canonicalization, AES-256-GCM encryption, Merkle trees (integrity), Prolly trees (state reconciliation), and Bloom filters (efficient sync).

### 1.1 Terminology

| Term | Meaning |
|------|---------|
| **Safebox** | An attested compute node running a measured disk image with SSH removed. Identified by a P-256 keypair bound to its attestation. |
| **Author** | A person or organization that publishes software. Identified by one or more P-256 or secp256k1 keypairs. |
| **Peer** | Any Safenet node (Safebox or registry mirror). |
| **Namespace** | A scoped identifier for packages (e.g., `qbix/`, `alice/`). Owned by an author. |
| **Package** | A named, versioned unit of software under a namespace (e.g., `qbix/platform@3.2.1`). |
| **Publication** | An OCP claim asserting that a specific package version exists, with its content Merkle root. |
| **Safebux** | Off-chain payment credits denominated in OCP Payment claims. |
| **Drop** | A Safecloud storage node that stores opaque encrypted chunks. |
| **Jet** | An attested Safebox acting as a Safecloud content mirror. |

### 1.2 Design Principles

1. **Storage is orthogonal to authorization.** Safecloud stores encrypted chunks; Safenet distributes keys and trust. Drops never need attestation — they serve opaque data.
2. **Claims, not accounts.** Identity is cryptographic, not username/password. An author is their signing key(s). A Safebox is its attestation-bound keypair.
3. **Git-native publishing.** Authors publish by pushing to a git remote. The registry is a signing and distribution layer, not a replacement for version control.
4. **Offline-first.** Every Safebox maintains a local replica of the registry state it needs. Sync is eventual and partition-tolerant.
5. **OCP everywhere.** Every assertion (publication, payment, trust, revocation) is an OCP claim — verifiable by any party with the signer's public key.

---

## 2. Identity Layer

### 2.1 Safebox Identity

A Safebox's identity is a P-256 keypair generated at first boot and bound to its attestation measurements (PCR values). The public key is published as an OCP claim:

```json
{
  "ocp": 1,
  "iss": "safebox://<spki-hash>",
  "sub": "safebox://<spki-hash>",
  "stm": {
    "type": "safebox_identity",
    "publicKey": "<spki-base64>",
    "pcr0": "<hex>",
    "pcr1": "<hex>",
    "pcr4": "<hex>",
    "imageHash": "<hex>",
    "endpoints": ["https://safebox1.example.com:8443"],
    "capabilities": ["registry", "mirror", "git-receiver"],
    "version": "1.0.0"
  },
  "key": ["data:key/es256;base64,<spki-base64>"],
  "sig": ["<base64>"]
}
```

**Safebox URI scheme:** `safebox://<spki-hash>` where `spki-hash` is `SHA-256(spki-base64)` encoded as hex. This is stable across IP changes and reboots.

### 2.2 Author Identity

Authors are identified by their signing keys. An author identity claim establishes a human-readable name bound to one or more keys:

```json
{
  "ocp": 1,
  "iss": "safenet:author:<name>",
  "sub": "safenet:author:<name>",
  "stm": {
    "type": "author_identity",
    "name": "alice",
    "displayName": "Alice Chen",
    "keys": [
      {
        "keyUri": "data:key/es256;base64,<spki>",
        "role": "primary",
        "addedAt": "2026-01-15T00:00:00Z"
      },
      {
        "keyUri": "data:key/eip712,0xabc...",
        "role": "payment",
        "addedAt": "2026-01-15T00:00:00Z"
      }
    ],
    "recovery": {
      "threshold": { "m": 2, "n": 3 },
      "keys": ["data:key/es256;base64,<recovery1>", "data:key/es256;base64,<recovery2>", "data:key/es256;base64,<recovery3>"]
    },
    "secondFactor": "webauthn"
  },
  "key": ["data:key/es256;base64,<spki>"],
  "sig": ["<base64>"]
}
```

**Author name rules:**
- Lowercase alphanumeric plus hyphens: `[a-z0-9][a-z0-9-]{0,62}[a-z0-9]`
- Cannot start or end with hyphen
- Cannot contain consecutive hyphens
- Reserved prefixes: `safebox-`, `safenet-`, `system-`

### 2.3 Organization Identity

Organizations are multi-key author identities with governance thresholds:

```json
{
  "ocp": 1,
  "iss": "safenet:org:<name>",
  "sub": "safenet:org:<name>",
  "stm": {
    "type": "org_identity",
    "name": "qbix",
    "displayName": "Qbix, Inc.",
    "members": {
      "alice": { "keyUri": "data:key/es256;base64,<spki>", "role": "admin" },
      "bob": { "keyUri": "data:key/es256;base64,<spki>", "role": "publisher" }
    },
    "thresholds": {
      "publish": { "m": 1, "n": 2 },
      "namespace": { "m": 2, "n": 2 },
      "member": { "m": 2, "n": 2 }
    }
  },
  "key": ["data:key/es256;base64,<alice-spki>", "data:key/es256;base64,<bob-spki>"],
  "sig": ["<alice-sig>", "<bob-sig>"]
}
```

---

## 3. Trust Establishment

### 3.1 Mutual Attestation

When two Safeboxes connect, they perform mutual attestation before exchanging registry data or proprietary content. The handshake runs over HTTPS (TLS 1.3):

```
Safebox A                          Safebox B
    |                                  |
    |--- TLS ClientHello ------------>|
    |<-- TLS ServerHello + Cert ------|
    |--- TLS Finished --------------->|
    |                                  |
    |--- POST /safenet/v1/attest ---->|
    |    Body: { identity_claim_A }    |
    |<-- 200 { identity_claim_B } ----|
    |                                  |
    |--- POST /safenet/v1/challenge ->|
    |    Body: { nonce_A }             |
    |<-- 200 { nonce_B,               |
    |          proof_B: sign(nonce_A,  |
    |            identity_B) }         |
    |                                  |
    |--- POST /safenet/v1/verify ---->|
    |    Body: { proof_A:              |
    |      sign(nonce_B, identity_A) } |
    |<-- 200 { trusted: true }         |
```

**Verification steps for each side:**
1. Verify the peer's identity claim (OCP signature check).
2. Verify the peer's PCR values match an acceptable image set.
3. Verify the challenge response (proof that the peer holds the private key matching its identity claim).
4. Check the peer against known revocations.
5. If all pass, mark the peer as trusted for this session.

### 3.2 Trust Levels

| Level | Meaning | Requires |
|-------|---------|----------|
| `untrusted` | No attestation performed | Default |
| `attested` | Mutual attestation passed | Valid identity + PCR match |
| `endorsed` | Governance quorum has endorsed this Safebox | Attested + governance endorsement claim |
| `delegated` | Holds a valid delegation chain from a trusted root | Attested + delegation chain verification |

### 3.3 Acceptable Image Registry

Each Safebox maintains a set of acceptable image hashes (disk images that are considered trustworthy). This is updated via governance claims:

```json
{
  "ocp": 1,
  "iss": "safenet:governance",
  "sub": "safenet:images",
  "stm": {
    "type": "image_blessing",
    "imageHash": "<sha256-hex>",
    "version": "2.1.0",
    "description": "Infrastructure image v2.1.0 with latest security patches"
  },
  "key": ["<gov-key-1>", "<gov-key-2>", "<gov-key-3>"],
  "sig": ["<sig-1>", "<sig-2>", "<sig-3>"]
}
```

Verified against the governance key registry with the `system` threshold.

---

## 4. Package Registry

### 4.1 State Model

The registry state is a Prolly tree (probabilistic B-tree) mapping package identifiers to their metadata. Every peer maintains a local replica. The Prolly tree enables efficient O(diff × log n) synchronization — peers exchange only the subtrees that differ.

**Prolly tree key space:**

```
namespace:<name>                → NamespaceClaim
package:<namespace>/<name>      → PackageMetadata
version:<namespace>/<name>@<v>  → PublicationClaim
author:<name>                   → AuthorIdentityClaim
revocation:<hash>               → RevocationClaim
```

**Root hash:** The Prolly tree root hash is the canonical identifier for the registry state at a point in time. Peers compare root hashes to detect divergence.

### 4.2 Namespace Claims

Before publishing packages, an author must claim a namespace:

```json
{
  "ocp": 1,
  "iss": "safenet:author:alice",
  "sub": "safenet:namespace:alice",
  "stm": {
    "type": "namespace_claim",
    "namespace": "alice",
    "owner": "safenet:author:alice",
    "claimedAt": "2026-01-15T00:00:00Z"
  },
  "key": ["data:key/es256;base64,<alice-spki>"],
  "sig": ["<alice-sig>"]
}
```

**Conflict resolution:** First-come-first-served with tie-breaking by claim timestamp. If two claims for the same namespace arrive at a peer with identical timestamps, the one with the lexicographically smaller key URI wins.

**Namespace transfer:** The current owner signs a transfer claim naming the new owner. The new owner must counter-sign.

### 4.3 Package Metadata

Each package has a metadata record in the registry:

```json
{
  "namespace": "alice",
  "name": "my-library",
  "description": "A utility library for distributed systems",
  "languages": ["nodejs", "php"],
  "license": "MIT",
  "safeboxOnly": false,
  "pricing": {
    "model": "free"
  },
  "latestVersions": {
    "stable": "1.2.3",
    "beta": "1.3.0-beta.1"
  },
  "createdAt": "2026-02-01T00:00:00Z",
  "updatedAt": "2026-09-15T00:00:00Z"
}
```

### 4.4 Version Identifiers

Versions follow [SemVer 2.0.0](https://semver.org/):

```
MAJOR.MINOR.PATCH[-prerelease][+build]
```

Version ordering and range matching use standard semver rules. The registry stores each version as a separate Prolly tree entry, keyed by `version:<namespace>/<name>@<version>`.

---

## 5. Publication Protocol

### 5.1 Publication Flow

```
Author's machine              Safenet Git Receiver         Registry Peers
      |                              |                          |
      |-- git push safenet main ---->|                          |
      |                              |                          |
      |                    [receive pack]                       |
      |                    [verify author identity]             |
      |                    [verify namespace ownership]         |
      |                    [verify 2FA if enabled]              |
      |                    [extract manifest]                   |
      |                    [compute content Merkle root]        |
      |                    [sign publication claim]             |
      |                              |                          |
      |<-- push accepted ------------|                          |
      |                              |                          |
      |                              |-- gossip publication --->|
      |                              |       claim to peers     |
      |                              |                          |
      |                              |-- store content in  ---->|
      |                              |   Safecloud (encrypted)  |
```

### 5.2 Package Manifest

Every package version must include a `safenet.json` manifest at the repository root:

```json
{
  "name": "alice/my-library",
  "version": "1.2.3",
  "description": "A utility library for distributed systems",
  "languages": {
    "nodejs": {
      "entry": "index.js",
      "engines": { "node": ">=18.0.0" },
      "dependencies": {
        "qbix/platform": "^3.0.0"
      }
    },
    "php": {
      "entry": "src/MyLibrary.php",
      "require": { "php": ">=8.1" },
      "dependencies": {
        "qbix/platform": "^3.0.0"
      }
    }
  },
  "license": "MIT",
  "safeboxOnly": false,
  "pricing": {
    "model": "per-install",
    "amount": "100",
    "currency": "safebux"
  },
  "compatibility": {
    "infrastructure": ">=2.0.0",
    "safenet": ">=0.1.0"
  },
  "repository": "https://github.com/alice/my-library",
  "authors": [
    { "name": "Alice Chen", "key": "data:key/es256;base64,<spki>" }
  ]
}
```

### 5.3 Publication Claim

The signed claim that enters the registry:

```json
{
  "ocp": 1,
  "iss": "safenet:author:alice",
  "sub": "safenet:pkg:alice/my-library@1.2.3",
  "stm": {
    "type": "publication",
    "namespace": "alice",
    "package": "my-library",
    "version": "1.2.3",
    "merkleRoot": "<sha256-hex-of-content-tree>",
    "manifestHash": "<sha256-hex-of-safenet.json>",
    "languages": ["nodejs", "php"],
    "license": "MIT",
    "safeboxOnly": false,
    "contentSize": 145280,
    "fileCount": 42,
    "dependencies": {
      "qbix/platform": "^3.0.0"
    },
    "pricing": {
      "model": "per-install",
      "amount": "100",
      "currency": "safebux"
    },
    "previousVersion": "1.2.2",
    "previousMerkleRoot": "<hex>",
    "publishedAt": "2026-09-15T14:30:00Z"
  },
  "key": ["data:key/es256;base64,<alice-spki>"],
  "sig": ["<alice-sig>"],
  "nbf": "2026-09-15T14:30:00Z"
}
```

### 5.4 Content Storage

Package content is stored in Safecloud as encrypted chunks:

1. The git pack is split into fixed-size chunks (default 256 KiB).
2. Each chunk is encrypted with AES-256-GCM using a key derived from: `HKDF-SHA256(packageSecret, salt=chunkIndex, info="safenet-chunk-v1")`.
3. The `packageSecret` for open-source packages is derived from: `HKDF-SHA256(merkleRoot, salt="safenet", info="safenet-package-key-v1")` — anyone with the Merkle root can derive it.
4. The `packageSecret` for proprietary (`safeboxOnly: true`) packages is distributed only to attested Safeboxes that hold a valid license grant (see Section 7).
5. Chunk references (content hashes) are listed in the publication claim's supplementary data, enabling any Safecloud drop to store and serve them.

### 5.5 Content Merkle Tree

The content Merkle tree provides integrity verification for the package:

- Leaves are `SHA-256(0x00 || fileContent)` for each file in the package, ordered by path.
- Parents are `SHA-256(0x01 || left || right)`, with odd nodes paired with themselves.
- The root hash is included in the publication claim.
- Inclusion proofs allow verifying individual files without downloading the entire package.

This uses the same construction as `Q.Data.Merkle`.

---

## 6. Git and Mercurial Integration

### 6.1 Git Smart HTTP Protocol

Safenet acts as a Git Smart HTTP server. Authors configure a remote:

```bash
git remote add safenet https://safebox.example.com/safenet/v1/git/alice/my-library
```

The server implements the Git Smart HTTP endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/info/refs?service=git-receive-pack` | GET | Advertise refs for push |
| `/info/refs?service=git-upload-pack` | GET | Advertise refs for fetch |
| `/git-receive-pack` | POST | Receive pushed commits |
| `/git-upload-pack` | POST | Serve fetched commits |

### 6.2 Push Authentication

Git push authentication uses OCP claims in the HTTP Authorization header:

```
Authorization: OCP <base64-encoded-ocp-claim>
```

The claim asserts the author's identity and is verified against the namespace ownership registry. The claim must be fresh (within 5 minutes of `nbf`).

Alternatively, authors can use SSH-style public key authentication with the key registered in their author identity claim.

### 6.3 Push Hooks

On receiving a push:

1. **Pre-receive:** Verify author identity and namespace ownership.
2. **Update:** For each ref being updated:
   - Parse `safenet.json` from the new commit.
   - Validate version bump rules (no re-publishing existing versions).
   - Validate manifest schema.
3. **Post-receive:** 
   - Compute content Merkle root.
   - Sign and store the publication claim.
   - Encrypt and distribute content chunks to Safecloud.
   - Gossip the publication claim to peers.

### 6.4 Mercurial Support

Mercurial integration follows the same pattern using Mercurial's wire protocol over HTTP. The server implements:

- `capabilities` — Advertise supported commands
- `unbundle` — Receive pushed changesets
- `getbundle` — Serve fetched changesets

Authentication and hooks are identical to the Git path.

### 6.5 Second Factor (2FA)

When an author has `secondFactor: "webauthn"` in their identity claim, pushes require a second factor. The flow:

1. Git push is received and paused at the pre-receive hook.
2. Server returns HTTP 401 with `WWW-Authenticate: OCP-2FA challenge=<nonce>`.
3. The git credential helper opens a browser to `https://safebox.example.com/safenet/v1/auth/2fa?challenge=<nonce>`.
4. Author completes WebAuthn challenge in the browser.
5. Server issues a short-lived (5-minute) bearer token.
6. Git retries the push with the bearer token.

---

## 7. Payment Protocol (Safebux)

### 7.1 Overview

Safebux is the payment unit for proprietary software licenses in Safenet. Payments are OCP claims that can accumulate off-chain and optionally settle on any EVM blockchain via the OpenClaiming Payments contract.

### 7.2 License Grant

A license grant authorizes a Safebox to install a proprietary package:

```json
{
  "ocp": 1,
  "iss": "safenet:author:alice",
  "sub": "safebox://<safebox-spki-hash>",
  "stm": {
    "type": "license_grant",
    "package": "alice/proprietary-lib",
    "versionRange": "^1.0.0",
    "maxInstalls": 1,
    "grantedAt": "2026-09-15T14:30:00Z"
  },
  "key": ["data:key/es256;base64,<alice-spki>"],
  "sig": ["<alice-sig>"],
  "exp": "2027-09-15T14:30:00Z"
}
```

### 7.3 Payment Claim

When a Safebox installs a paid package, it issues a payment claim:

```json
{
  "ocp": 1,
  "iss": "safebox://<safebox-spki-hash>",
  "sub": "safenet:author:alice",
  "stm": {
    "type": "payment",
    "package": "alice/proprietary-lib",
    "version": "1.2.3",
    "amount": "100",
    "currency": "safebux",
    "installId": "<uuid>",
    "paidAt": "2026-09-15T15:00:00Z"
  },
  "key": ["data:key/es256;base64,<safebox-spki>"],
  "sig": ["<safebox-sig>"]
}
```

### 7.4 Safebux Accounting

Safebux are tracked as a directed graph of payment claims:

- Each Safebox maintains a local ledger of payments made and received.
- Peers gossip payment claims alongside publication claims.
- An author's Safebux balance is the sum of all verified payment claims where `sub` matches their identity.

### 7.5 On-Chain Settlement

Authors can redeem Safebux on any EVM chain via the OpenClaiming Payments contract:

1. Author aggregates payment claims into a batch.
2. Author creates an EIP-712 Payment claim naming the OpenClaiming contract.
3. The payer (Safebox operator) signs the EIP-712 payment authorizing the transfer.
4. Author submits the batch to the OpenClaiming contract, which verifies signatures and executes ERC-20 transfers.

```json
{
  "ocp": 1,
  "fmt": "EIP712",
  "iss": "evm:1:address:0x<payer>",
  "sub": "evm:1:address:0x<recipient>",
  "stm": {
    "type": "payment",
    "chainId": "1",
    "verifyingContract": "0x99999febd42cad798fe10ab0b1c563002fc99999",
    "recipients": ["evm:1:address:0x<recipient>"],
    "max": "10000",
    "line": "0"
  },
  "key": ["data:key/eip712,evm:1:address:0x<payer>"],
  "sig": ["0x<eip712-sig>"],
  "nbf": "1695000000",
  "exp": "1700000000"
}
```

### 7.6 Pricing Models

| Model | Description | Payment Timing |
|-------|-------------|----------------|
| `free` | No payment required | — |
| `per-install` | Fixed fee per Safebox installation | On install |
| `subscription` | Recurring payment per time period | On install + periodic renewal |
| `metered` | Pay per API call or compute unit | Periodic settlement |

---

## 8. Discovery and Synchronization

### 8.1 Peer Discovery

Safeboxes discover each other through:

1. **Bootstrap peers:** A hardcoded list of well-known Safenet peers (similar to DNS seeds in Bitcoin).
2. **Peer exchange:** On connection, peers exchange their known peer lists.
3. **DNS-SD:** `_safenet._tcp` service records for local network discovery.
4. **Governance claims:** Governance quorum can publish `peer_announce` claims.

### 8.2 Gossip Protocol

Publications, revocations, and peer announcements propagate via epidemic gossip:

1. When a peer receives a new claim, it validates it.
2. If valid, it stores the claim in its local Prolly tree.
3. It forwards the claim to `fanout` random peers (default: `fanout = 6`).
4. Each peer deduplicates by claim hash (`SHA-256(canonicalize(stm))`).
5. TTL limits propagation depth (default: 8 hops).

### 8.3 Bloom-Accelerated Sync

For initial sync or reconnection after partition, peers use Bloom filters:

1. Peer A sends a Bloom filter of its known publication claim hashes.
2. Peer B tests each of its claims against A's filter.
3. B sends back claims that are probably missing from A (false positives are harmless — A ignores duplicates).
4. A reciprocates.

Bloom filter parameters: `n` = expected elements, `p` = 0.001 (0.1% false positive rate). Uses `Q.Data.Bloom`.

### 8.4 Prolly Tree Reconciliation

For fine-grained sync, peers compare Prolly tree root hashes and exchange only divergent subtrees:

1. Peer A sends its Prolly tree root hash.
2. If B's root hash differs, they perform a tree diff.
3. `Q.Data.Prolly.diff(rootA, rootB)` returns only the changed entries.
4. Peers exchange the missing entries and merge.

**Merge rules:**
- Claims are immutable once published; conflicts are resolved by timestamp then key URI.
- Revocations always win over the claims they revoke.
- Namespace claims are first-come-first-served.

---

## 9. Revocation

### 9.1 Key Revocation

An author revokes one of their keys:

```json
{
  "ocp": 1,
  "iss": "safenet:author:alice",
  "sub": "safenet:author:alice",
  "stm": {
    "type": "key_revocation",
    "revokedKey": "data:key/es256;base64,<compromised-spki>",
    "reason": "key_compromise",
    "effectiveAt": "2026-09-15T14:30:00Z",
    "invalidatePublicationsAfter": "2026-09-01T00:00:00Z"
  },
  "key": ["data:key/es256;base64,<alice-current-spki>"],
  "sig": ["<alice-sig>"]
}
```

Must be signed by a key other than the revoked key, or by the recovery quorum.

### 9.2 Package Revocation

An author withdraws a package version:

```json
{
  "ocp": 1,
  "iss": "safenet:author:alice",
  "sub": "safenet:pkg:alice/my-library@1.2.3",
  "stm": {
    "type": "package_revocation",
    "package": "alice/my-library",
    "version": "1.2.3",
    "reason": "security_vulnerability",
    "advisory": "Buffer overflow in parse() allows remote code execution",
    "replacement": "1.2.4"
  },
  "key": ["data:key/es256;base64,<alice-spki>"],
  "sig": ["<alice-sig>"]
}
```

### 9.3 Safebox Revocation

The governance quorum can revoke a Safebox's trust:

```json
{
  "ocp": 1,
  "iss": "safenet:governance",
  "sub": "safebox://<compromised-spki-hash>",
  "stm": {
    "type": "safebox_revocation",
    "reason": "attestation_failure",
    "effectiveAt": "2026-09-15T14:30:00Z"
  },
  "key": ["<gov-key-1>", "<gov-key-2>", "<gov-key-3>"],
  "sig": ["<sig-1>", "<sig-2>", "<sig-3>"]
}
```

Requires the `system` governance threshold.

### 9.4 Revocation Propagation

Revocations are priority-gossiped: forwarded to all known peers immediately (not subject to `fanout` limit) with a higher TTL (16 hops). Peers must process revocations before processing any pending claims.

---

## 10. Transparency Log

### 10.1 Publication Log

Every Safenet peer maintains a Merkle-tree-based append-only log of all publications it has witnessed. This provides:

- **Auditability:** Any party can verify that a publication existed at a certain time.
- **Non-equivocation:** A peer cannot present different histories to different parties without detection (compare Merkle roots).
- **Consistency proof:** New entries can be verified against the existing log root.

Log structure:

```
Entry N: SHA-256(entry_{N-1}_hash || claim_hash || timestamp)
```

### 10.2 Public Audit Endpoints

Every Safenet peer exposes:

| Endpoint | Method | Response |
|----------|--------|----------|
| `/safenet/v1/transparency/root` | GET | Current log root hash and entry count |
| `/safenet/v1/transparency/entry/<n>` | GET | Entry N with inclusion proof |
| `/safenet/v1/transparency/consistency/<from>/<to>` | GET | Consistency proof between two tree sizes |
| `/safenet/v1/transparency/search?package=<name>` | GET | All publications for a package |

---

## 11. Wire Formats and API

### 11.1 Claim Types Summary

| `stm.type` | Issuer | Subject | Purpose |
|-------------|--------|---------|---------|
| `safebox_identity` | Safebox | Safebox | Declare identity + attestation |
| `author_identity` | Author | Author | Declare author keys + metadata |
| `org_identity` | Org members | Org | Declare org membership + thresholds |
| `namespace_claim` | Author/Org | Namespace | Claim ownership of a namespace |
| `publication` | Author/Org | Package@version | Publish a package version |
| `license_grant` | Author/Org | Safebox | Grant install permission |
| `payment` | Safebox | Author/Org | Pay for installation |
| `key_revocation` | Author/Org | Author/Org | Revoke a signing key |
| `package_revocation` | Author/Org | Package@version | Withdraw a package version |
| `safebox_revocation` | Governance | Safebox | Revoke Safebox trust |
| `image_blessing` | Governance | Image hash | Approve a disk image |
| `peer_announce` | Safebox | Safebox | Announce network presence |
| `trust` | Safebox | Safebox | Establish trust relationship |
| `namespace_transfer` | Author/Org | Namespace | Transfer namespace ownership |

### 11.2 HTTP API

All Safenet endpoints are under `/safenet/v1/`. Content type is `application/json`.

**Registry:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/registry/namespace/<name>` | Get namespace claim |
| GET | `/registry/package/<ns>/<name>` | Get package metadata |
| GET | `/registry/package/<ns>/<name>/versions` | List versions |
| GET | `/registry/package/<ns>/<name>/<version>` | Get publication claim |
| GET | `/registry/search?q=<query>&lang=<lang>` | Search packages |
| GET | `/registry/root` | Get Prolly tree root hash |

**Publication (authenticated):**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/publish` | Submit a signed publication claim |
| POST | `/namespace/claim` | Claim a namespace |
| POST | `/namespace/transfer` | Transfer a namespace |

**Git:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/git/<ns>/<name>/info/refs` | Git ref advertisement |
| POST | `/git/<ns>/<name>/git-receive-pack` | Git push |
| POST | `/git/<ns>/<name>/git-upload-pack` | Git fetch |

**Peer-to-Peer:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/attest` | Exchange identity claims |
| POST | `/challenge` | Attestation challenge |
| POST | `/verify` | Attestation verification |
| POST | `/gossip` | Receive gossiped claims |
| POST | `/sync/bloom` | Bloom filter exchange |
| POST | `/sync/prolly` | Prolly tree reconciliation |
| GET | `/peers` | Get known peer list |

**Payments:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/pay` | Submit a payment claim |
| GET | `/balance/<author>` | Get Safebux balance |
| GET | `/payments/<author>` | List payment claims |

**Transparency:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/transparency/root` | Current log root |
| GET | `/transparency/entry/<n>` | Entry with proof |
| GET | `/transparency/consistency/<from>/<to>` | Consistency proof |

**Content:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/content/<merkleRoot>/<chunkIndex>` | Download content chunk |
| GET | `/content/<merkleRoot>/proof/<fileIndex>` | Merkle inclusion proof for a file |

---

## 12. Security Considerations

### 12.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Compromised Safebox | Mutual attestation + PCR verification. Governance revocation. BFT for registry integrity (< 1/3 compromised). |
| Author key compromise | Recovery quorum (M-of-N). Key revocation with retroactive invalidation. WebAuthn 2FA on publish. |
| Package supply chain attack | Content Merkle tree. Signed publication claims. Transparency log for auditability. |
| Eclipse attack on registry | Prolly tree root comparison across multiple peers. Consistency proofs. |
| Payment replay | Unique `installId` per payment. Timestamp bounds (`nbf`/`exp`). |
| Man-in-the-middle | TLS 1.3 with pinned Safebox certificates. OCP claim verification independent of transport. |
| Quantum threat | AES-256-GCM and HKDF-SHA256 are quantum-safe. P-256 ECDH is not — upgrade path: swap to ML-KEM (Kyber) for key exchange. Signatures: upgrade to ML-DSA (Dilithium) or SLH-DSA (SPHINCS+). OCP key URI scheme supports new algorithms via new `data:key/<algorithm>` media types. |

### 12.2 Rate Limiting

- Publication: Max 10 versions per package per hour.
- Gossip: Max 100 claims per peer per minute.
- Sync: Max 1 full sync per peer per hour; incremental sync unlimited.
- Git push: Max 5 pushes per author per hour per package.

### 12.3 Claim Validation Rules

Every claim must pass before being accepted into the registry:

1. `ocp` must be `1`.
2. `stm.type` must be a recognized type.
3. If `nbf` is set, current time must be ≥ `nbf`.
4. If `exp` is set, current time must be < `exp`.
5. At least one signature must be valid.
6. The signer must be authorized for the claim type (e.g., only namespace owners can publish to their namespace).
7. The claim must not be revoked.
8. For governance claims, the governance threshold must be met.

---

## 13. Compatibility and Evolution

### 13.1 Protocol Versioning

The protocol version is carried in the URL path (`/safenet/v1/`). Breaking changes increment the version. Non-breaking additions (new claim types, new optional fields) do not.

### 13.2 Claim Type Extensions

New claim types can be introduced without protocol version bumps. Unknown claim types are stored but not processed — they are forwarded during gossip to support heterogeneous upgrade.

### 13.3 Cryptographic Agility

The OCP key URI scheme (`data:key/<algorithm>;base64,<value>`) provides cryptographic agility. New algorithms can be added (e.g., `data:key/ml-dsa65;base64,<pk>` for post-quantum signatures) without changing the wire format.

---

## Appendix A: Reference Implementation

The reference implementation is in Node.js and uses:

- `Q.Crypto` — OCP signing and verification, deterministic keypairs, delegation
- `Q.Crypto.OpenClaim` — OCP claim construction and verification
- `Q.Data` — Canonicalization, HKDF, AES-256-GCM, Merkle trees
- `Q.Data.Prolly` — Prolly tree for registry state
- `Q.Data.Bloom` — Bloom filters for sync

See the `lib/` directory for the implementation modules.

## Appendix B: Claim Canonicalization

Claims are canonicalized per RFC 8785 (JSON Canonicalization Scheme) before signing:

1. Remove the `sig` field.
2. Sort all object keys lexicographically, recursively.
3. Serialize numbers per ES2015 `Number.toString()`.
4. No whitespace between tokens.

The canonical form is the byte string that is signed. This matches `Q.Data.canonicalize()` and `Q.Crypto.OpenClaim`'s existing behavior.

## Appendix C: HKDF Key Derivation Tree

```
rootSecret (per Safebox)
  ├── HKDF(info="safebox-identity-v1")     → Safebox identity keypair
  ├── HKDF(info="safebox-gateway-hmac-v1") → Gateway HMAC key (existing)
  ├── HKDF(info="safenet-peer-v1")         → Peer-to-peer TLS key
  └── HKDF(info="safenet-content-v1")      → Content encryption master key
       ├── HKDF(info="pkg:<ns>/<name>@<v>") → Package-specific key
       │    ├── HKDF(info="chunk:0")         → Chunk 0 key
       │    ├── HKDF(info="chunk:1")         → Chunk 1 key
       │    └── ...
       └── ...
```

## Appendix D: Safenet URIs

```
safebox://<spki-hash>                    — Safebox identity
safenet:author:<name>                    — Author identity
safenet:org:<name>                       — Organization identity
safenet:namespace:<name>                 — Namespace
safenet:pkg:<namespace>/<name>           — Package (latest)
safenet:pkg:<namespace>/<name>@<version> — Package version
safenet:governance                       — Governance quorum
safenet:images                           — Approved image set
```
