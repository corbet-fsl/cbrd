# cbrd: Board

Thin composition of Link, Profile, Envelope, Exchange, Search, Groups and Attend. Board is the single member facade reaching the Forum and has no duplicate profile, index, roster or policy engine.

Implementation is in progress. No integration or coverage acceptance is claimed.

Board now holds one Link and delegates same-community local validation and
give-first inspection to their owners. Groups and Attend consumer types are
reexported directly; their runtime adapters remain unavailable. See the
[contract](docs/CONTRACT.md) for implemented and pending boundaries.

## Scope

Board is the member facade for profiles, presence, discovery, private-profile
exchange, groups and public rooms. It wires Link, Profile, Envelope, Exchange,
Search, Groups, Attend and Compression, and delivers committed block, change and
departure events to their owners in order. Contacts owns blocking relationships;
Guard owns validation and matching.

Link alone owns all Forum connections. Its authenticated presence/forum session
and anonymous public-room session must be unlinkable; anonymous rooms use blind
room passes. No child opens an independent Forum client. Board owns no profile,
index, roster, presence switch, matching engine or duplicate authority.

Its state is derived: offline, needs profile or credential, present, or needs
resynchronization. Ports cover profile/rules, presence/discovery, exchange,
GroupView, consent/fork/suggestion and rooms. Tests must demonstrate committed event
ordering, community isolation, no profile keys at Forum, both session classes
through Link, group policy/consent and listing handover. Current local composition
and unavailable adapters are listed in [the contract](docs/CONTRACT.md).

Board accepts the Link owner’s typed anonymous-client attachment while retaining
exactly one Link. Its room status remains unavailable until the actual Attend
authority and shared transaction adapter are connected.

## Unreleased runtime successor

The integration candidate adds actual challenge/enter and per-request signing
ports through Link, with injected time and original Forum wire types. Native and
browser HTTPS transports are owned by Forum and reexported through Link. Link
keeps no private signing key, clears cancelled/expired/refused attendance and does
not retry ambiguous effects. Graceful departure uses an actual signed Depart;
`disconnect` clears local state and leaves an unreachable server lease to expire.
Board rechecks received original publications through Search before returning a
page, and checks exact Profile revision/ciphertext binding on retrieval. New paths
are uncompiled pending owner main releases; no complete coverage or live delivery
is claimed. Incremental delta handling, Mesh key-release composition and anonymous
room authority remain integration work.

The current source separates async `receive_search`/`receive_watch`/
`receive_ciphertext` from synchronous `finish_search`/`finish_watch`/
`finish_ciphertext`. Pending outputs have no serializer or content accessor.
After network completion the runtime rebuilds the original current Charter/Guard
and reloads the exact committed Profile, then finishes with those actual owners.
Finishers and display reads require the original Link clock second to equal the
verification time. Watch is bound to the last held opaque window cursor; Search
owns bounded delta application. Committed local removals invalidate that polling
baseline immediately. Raw generic execute refuses search/watch/ciphertext.
Written actual-server vectors cover joins/leaves, stale-clock response refusal,
real revocation between receive and finish, and original anonymous pass custody.
They have not yet been compiled or executed. G2 currentness, HPKE Exchange,
original member MLS and full qualified source gates still remain integration work.

The `ReadContext` adapter is the cmsg-facing completion path. It borrows the
actual unlocked Store, current Keys Binding, Foyer's one VerifiedCharter and
original contact detector; `ReadPolicy` requires the trusted deployment action
and maximum snapshot age in seconds. `finish_search_committed`,
`finish_watch_committed`, `finish_ciphertext_committed` and
`read_discovery_committed` load the canonical Profile through its own
`load_current_committed` port and build current Charter policy inside Board.
No shell supplies an own publication, floor or Guard policy. Original finishers
still check exact Link attendance/publication, reciprocal matching and envelope
binding. Clock is checked again before returning, and any refusal clears the
held view. The parent must reconcile actual Vault/Keys freshness and current G3
before borrowing; this adapter does not manufacture G2 or G3 authority.
