# Board composition contract

Board binds one device/community runtime and owns one Link. It delegates local
public-pair validation to Search and give-first inspection to Exchange. Those
owners use Profile/Envelope/Guard; Board copies none of their logic or data.
Every delegated verification must use this Board's fixed community.

`Status` reflects Link's actual connection state and explicitly unavailable
Groups/rooms runtime adapters. `GroupView` and `RoomPhase` are direct reexports
from Groups and Attend for generated consumer schemas, not copied DTOs.

Implemented: same-community composition and local validation/inspection, plus
generated-client challenge forwarding. Pending: production current
presence/discovery, Contacts block event plumbing, combined encrypted
candidate/checkpoint, Groups lifecycle and Attend/Threads ordered room adapters.
No external notice or key release occurs from local inspection; no fixture
policy or ready status fills an absent capability. Profile/Contacts/Wallet keep
their own custody, journals and authority. Link remains the sole Forum connection owner, with separate unlinkable
authenticated presence/forum and anonymous blind-pass room sessions. Board can retain `Link<Auth, AnonymousRooms<Rooms>>` from the actual Link owner
without exposing either client. Link routes the generated anonymous request DTOs;
Board still exposes no room operation until the current Attend authority and
combined checkpoint adapter exist. Configuring the second client does not make
`Status.rooms` available or prove real HTTPS session unlinkability.

Tests exercise real signed Profile preparation/checkpoints, Guard reciprocity
and Envelope opening across both facade paths on native and actual Wasm.
Injected transport refusal only exercises offline propagation; it is not
network, G3, room or end-to-end evidence.
