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
