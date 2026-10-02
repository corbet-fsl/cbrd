# cbrd: Board

Thin composition of Link, Profile, Envelope, Exchange, Search, Groups and Attend. Board is the single member facade reaching the Forum and has no duplicate profile, index, roster or policy engine.

Implementation is in progress. No integration or coverage acceptance is claimed.

Board now holds one Link and delegates same-community local validation and
give-first inspection to their owners. Groups and Attend consumer types are
reexported directly; their runtime adapters remain unavailable. See the
[contract](docs/CONTRACT.md) for implemented and pending boundaries.

## Scope

### Purpose

cbrd Board is the member-side forum facade and the only member facade that connects to cfrm, covering profile, presence, discovery, private-profile exchange, groups and public rooms through one Link.

### Owns

Wiring of Link, Profile, Envelope, Exchange, Search, Groups, Attend and Compression, and delivery of block, change and departure events to their owners in committed order. It uses blocking rules from Contacts and validation from Guard.

### Never

No second cfrm client for any child. No duplicate profile, index or roster, no ownership of contacts, and no matching implementation. No presence switch or presence library: connecting is presence. No content-check library: content checks belong to Guard. Only Board talks to cfrm, and keys never reach cfrm.

### States

Derived states only: Offline, NeedsProfileOrCredential, Present, NeedsResync.

### Test obligations

Block, change and departure events reach children in committed order; profile keys never reach cfrm; discovery, exchange and room joins work through one Link; Vault, Foyer and Inbox have no forum dependency; group consent, policy bands and listing handover are covered. Shared obligations apply: native and WebAssembly builds with identical test vectors, explicit state machines with injected clock, randomness, storage and network, thin facades with no duplicated state or crypto, full line and branch coverage with real round trips and injected delay, duplication, loss, cancellation, clock regression, corruption and storage conflicts, atomic publication with acknowledgement only after durable acceptance and reconciliation of unknown outcomes, strict per-community isolation, bounded bytes, queues and work with no identifiers, plaintext or secrets in errors, reuse of maintained third-party code with no own crypto, and no personal identifiers in outbound requests.
