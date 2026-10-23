//! Member rooms through Attend: Link ordering for the join, and the "here now"
//! count. Consent is a Groups join with the semipublic statement; MLS and the
//! key hand-over belong to Threads behind `ctnd::Threads`. Members see only how
//! many connections are present, never traffic volume or identities.
use crate::{Board, TransportKey};
use clnk::cmbl;
use ctnd::{Error, Link, OrderReply, OrderRequest, PortFuture};

fn operation(request: &OrderRequest, wrapped: &[u8]) -> cmbl::Id {
    // Deterministic, so an exact retry of the same order reaches Assembly's
    // original operation receipt instead of applying the commit twice.
    let mut hash = blake3::Hasher::new();
    hash.update(b"cbrd.room.order.v1\0");
    hash.update(&request.room);
    hash.update(&request.ordering);
    hash.update(&request.expected.to_be_bytes());
    hash.update(wrapped);
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    id
}

/// The one Link implementation for Attend: orders an encrypted commit through
/// the Board's anonymous room transport. A refusal after the request may have
/// reached the room is `Reconcile`, never a retry instruction.
pub struct RoomOrdering<'a, T, R> {
    board: &'a Board<T, clnk::AnonymousRooms<R>>,
    key: &'a TransportKey,
}
impl<'a, T: clnk::Transport, R: clnk::Transport> RoomOrdering<'a, T, R> {
    /// `key` is the room's epoch-derived transport key: the ordering server
    /// relays the join frames and sees only their ciphertext.
    pub fn new(board: &'a Board<T, clnk::AnonymousRooms<R>>, key: &'a TransportKey) -> Self {
        Self { board, key }
    }
}
impl<T: clnk::Transport, R: clnk::Transport> Link for RoomOrdering<'_, T, R> {
    fn order<'a>(&'a mut self, request: &'a OrderRequest) -> PortFuture<'a, OrderReply> {
        Box::pin(async move {
            let wrapped = self
                .key
                .wrap(
                    &request.room,
                    &ctnd::pack_ordered(&request.encrypted_commit, &request.companion),
                )
                .ok_or(Error::Unavailable)?;
            let command = cmbl::Request {
                room: request.room,
                operation: operation(request, &wrapped),
                action: cmbl::Action::Order {
                    expected: request.expected,
                    ciphertext: wrapped,
                },
            };
            match self.board.order_room(command, request.ordering).await {
                Ok(ordered) => Ok(OrderReply {
                    ordering: ordered.ordering(),
                    counter: ordered.counter(),
                    // Assembly returns no separate proof; Threads verifies the
                    // MLS evidence itself in `verify_order`.
                    proof: vec![],
                }),
                Err(
                    clnk::ErrorCode::Reconcile
                    | clnk::ErrorCode::Timeout
                    | clnk::ErrorCode::Transport,
                ) => Err(Error::Reconcile),
                Err(_) => Err(Error::Unavailable),
            }
        })
    }
}

impl<T: clnk::Transport, R: clnk::Transport> Board<T, clnk::AnonymousRooms<R>> {
    /// Order one encrypted room commit under the current pass.
    pub async fn order_room(
        &self,
        command: cmbl::Request,
        ordering: cmbl::Id,
    ) -> Result<clnk::OrderedRoom<'_>, clnk::ErrorCode> {
        self.link.order_room(command, ordering).await
    }

    /// A newcomer with a valid room pass asks the online members for the room
    /// state: its fresh ephemeral HPKE key goes on the room's anonymous
    /// transport. Returns the request's relay sequence, the handle for
    /// [`Self::room_join_answers`]. Nothing is published in the clear; with no
    /// member online the request expires and the caller retries.
    pub async fn request_room_join(
        &self,
        room: cmbl::Id,
        public_key: [u8; 32],
    ) -> Result<u64, clnk::ErrorCode> {
        let outcome = self
            .link
            .execute_room(cmbl::Request {
                room,
                operation: state_operation(&room, b"request", &public_key),
                action: cmbl::Action::Relay {
                    ciphertext: public_key.to_vec(),
                    kind: cmbl::FrameKind::JoinRequest,
                },
            })
            .await?;
        Ok(outcome.through)
    }

    /// Live join requests a member can answer: `(request, ephemeral key)`.
    pub async fn room_join_requests(
        &self,
        room: cmbl::Id,
    ) -> Result<Vec<(u64, [u8; 32])>, clnk::ErrorCode> {
        let outcome = self
            .link
            .execute_room(cmbl::Request {
                room,
                operation: state_operation(&room, b"requests", &[]),
                action: cmbl::Action::Read { after: 0 },
            })
            .await?;
        Ok(requests_in(&outcome))
    }

    /// A member answers request `to` with the room state sealed to the key in
    /// the request (see [`crate::join_seal`]).
    pub async fn answer_room_join(
        &self,
        room: cmbl::Id,
        to: u64,
        sealed: Vec<u8>,
    ) -> Result<(), clnk::ErrorCode> {
        self.link
            .execute_room(cmbl::Request {
                room,
                operation: state_operation(&room, b"answer", &sealed),
                action: cmbl::Action::Relay {
                    ciphertext: sealed,
                    kind: cmbl::FrameKind::RoomState { to },
                },
            })
            .await?;
        Ok(())
    }

    /// The sealed answers so far to request `to`: `(ordering generation,
    /// counter, sealed state)`. Several members may answer; the caller opens
    /// each and Threads verifies the evidence before any import.
    pub async fn room_join_answers(
        &self,
        room: cmbl::Id,
        to: u64,
    ) -> Result<Vec<(cmbl::Id, u64, Vec<u8>)>, clnk::ErrorCode> {
        let outcome = self
            .link
            .execute_room(cmbl::Request {
                room,
                operation: state_operation(&room, b"answers", &to.to_be_bytes()),
                action: cmbl::Action::Read {
                    after: to.saturating_sub(1),
                },
            })
            .await?;
        let ordering = outcome.ordering;
        Ok(answers_in(&outcome, &ordering, to)
            .map_err(|_| clnk::ErrorCode::Reconcile)?
            .into_iter()
            .map(|(counter, sealed)| (ordering, counter, sealed))
            .collect())
    }

    /// The newcomers' ordered external commits after relay sequence `after`,
    /// each with its authenticated companion (the signed Groups `Join` request):
    /// what an admitting member needs. Frames without a companion are not joins.
    pub async fn room_joins(
        &self,
        room: cmbl::Id,
        after: u64,
        key: &TransportKey,
    ) -> Result<JoinsRead, clnk::ErrorCode> {
        let outcome = self
            .link
            .execute_room(cmbl::Request {
                room,
                operation: state_operation(&room, b"joins", &after.to_be_bytes()),
                action: cmbl::Action::Read { after },
            })
            .await?;
        Ok(JoinsRead {
            joins: joins_in(&outcome, &room, key),
            through: outcome.through,
        })
    }

    /// How many connections are present in a room right now. Nothing else of the
    /// room crosses this call: no member list, no traffic, no frames.
    pub async fn here_now(
        &self,
        room: cmbl::Id,
        operation: cmbl::Id,
    ) -> Result<usize, clnk::ErrorCode> {
        let outcome = self
            .link
            .execute_room(cmbl::Request {
                room,
                operation,
                action: cmbl::Action::Read { after: u64::MAX },
            })
            .await?;
        Ok(outcome.active_connections)
    }

    /// Relay one room secret (an MLS application message) to the room, sealed
    /// under the room's transport key of the epoch it was sent in. The relay
    /// sees ciphertext only; an exact retry yields the same frame.
    pub async fn relay_room_secret(
        &self,
        room: cmbl::Id,
        key: &TransportKey,
        message: &[u8],
    ) -> Result<(), clnk::ErrorCode> {
        let mut plain = SECRET_MAGIC.to_vec();
        plain.extend_from_slice(message);
        let wrapped = key
            .wrap(&room, &plain)
            .ok_or(clnk::ErrorCode::Capacity)?;
        self.link
            .execute_room(cmbl::Request {
                room,
                operation: state_operation(&room, b"secret", &wrapped),
                action: cmbl::Action::Relay {
                    ciphertext: wrapped,
                    kind: cmbl::FrameKind::Message,
                },
            })
            .await?;
        Ok(())
    }

    /// The room secrets after relay sequence `after` that open under `key`
    /// (the transport key of this member's current epoch). Frames of another
    /// epoch or of another kind do not open and are skipped.
    pub async fn room_secrets(
        &self,
        room: cmbl::Id,
        after: u64,
        key: &TransportKey,
    ) -> Result<SecretsRead, clnk::ErrorCode> {
        let outcome = self
            .link
            .execute_room(cmbl::Request {
                room,
                operation: state_operation(&room, b"secrets", &after.to_be_bytes()),
                action: cmbl::Action::Read { after },
            })
            .await?;
        Ok(SecretsRead {
            secrets: secrets_in(&outcome, &room, key),
            through: outcome.through,
        })
    }

    /// Every member frame the room still holds, as the relay stores it: opaque
    /// ciphertext sealed under some epoch's transport key. This is the same
    /// room Read the admission loop makes; the caller opens a frame only with
    /// the key of the epoch it holds ([`RoomFrame::open`]). `gap` is true when
    /// the relay no longer holds the room's oldest frames.
    pub async fn room_frames(&self, room: cmbl::Id) -> Result<RoomFrames, clnk::ErrorCode> {
        let outcome = self
            .link
            .execute_room(cmbl::Request {
                room,
                operation: state_operation(&room, b"frames", &[]),
                action: cmbl::Action::Read { after: 0 },
            })
            .await?;
        Ok(room_frames_in(&outcome))
    }
}

/// The member frames of a room read, still sealed: requests and sealed room
/// state are no member traffic and are left out.
fn room_frames_in(outcome: &cmbl::Outcome) -> RoomFrames {
    RoomFrames {
        ordering: outcome.ordering,
        gap: outcome.gap,
        frames: outcome
            .frames
            .iter()
            .filter(|frame| frame.kind == cmbl::FrameKind::Message)
            .map(|frame| RoomFrame {
                sequence: frame.sequence,
                counter: frame.counter,
                ciphertext: frame.ciphertext.clone(),
            })
            .collect(),
    }
}

/// One member frame of a room, still sealed. Its sequence orders the room's
/// traffic; only the key of the epoch it was sealed in opens it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomFrame {
    pub sequence: u64,
    pub counter: u64,
    ciphertext: Vec<u8>,
}

/// The ordered commit inside a frame: the MLS commit and, for a newcomer's
/// external commit, the signed companion it authenticates (empty otherwise).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedCommit {
    pub commit: Vec<u8>,
    pub companion: Vec<u8>,
}

/// What a frame is for a member holding `key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameContent {
    /// An ordered commit (join or member commit).
    Commit(OrderedCommit),
    /// A room secret (an MLS application message).
    Secret,
}

impl RoomFrame {
    /// Open this frame under `key`, the transport key of the epoch the caller
    /// holds. `None` when it does not open (another epoch, or not ours).
    pub fn open(&self, room: &cmbl::Id, key: &TransportKey) -> Option<FrameContent> {
        let plain = key.unwrap(room, &self.ciphertext)?;
        if plain.starts_with(SECRET_MAGIC) {
            return Some(FrameContent::Secret);
        }
        let (commit, companion) = ctnd::unpack_ordered(&plain)?;
        Some(FrameContent::Commit(OrderedCommit {
            commit: commit.to_vec(),
            companion: companion.to_vec(),
        }))
    }
}

/// The member frames a room holds, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomFrames {
    /// The ordering generation the frames' counters belong to.
    pub ordering: cmbl::Id,
    /// The relay dropped the room's oldest frames: a member that needs them
    /// cannot catch up from the room.
    pub gap: bool,
    pub frames: Vec<RoomFrame>,
}

fn link_error(error: clnk::ErrorCode) -> Error {
    match error {
        clnk::ErrorCode::Reconcile | clnk::ErrorCode::Timeout | clnk::ErrorCode::Transport => {
            Error::Reconcile
        }
        _ => Error::Unavailable,
    }
}

fn read_operation(room: &cmbl::Id, after: u64, attempt: u8) -> cmbl::Id {
    let mut hash = blake3::Hasher::new();
    hash.update(b"cbrd.room.feed.v1\0");
    hash.update(room);
    hash.update(&after.to_be_bytes());
    hash.update(&[attempt]);
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    id
}

/// The ordered commit at `wanted`, if the room already holds it. Relay frames
/// carry the counter in force, so the first frame at `wanted` is the ordered
/// commit itself. A different ordering generation is never mixed in.
fn context_frame(
    outcome: &cmbl::Outcome,
    ordering: &cmbl::Id,
    wanted: u64,
    room: &cmbl::Id,
    key: &TransportKey,
) -> Result<Option<Vec<u8>>, Error> {
    if &outcome.ordering != ordering {
        return Err(Error::Reconcile);
    }
    Ok(outcome
        .frames
        .iter()
        .filter(|frame| frame.kind == cmbl::FrameKind::Message && frame.counter == wanted)
        .filter_map(|frame| key.unwrap(room, &frame.ciphertext))
        .find(|plain| !plain.starts_with(SECRET_MAGIC)))
}

/// A newcomer's ordered external commit with its companion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinFrame {
    pub ordering: cmbl::Id,
    pub counter: u64,
    pub commit: Vec<u8>,
    pub companion: Vec<u8>,
}
/// Joins found in one read and the relay sequence the read reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinsRead {
    pub joins: Vec<JoinFrame>,
    pub through: u64,
}

fn joins_in(outcome: &cmbl::Outcome, room: &cmbl::Id, key: &TransportKey) -> Vec<JoinFrame> {
    outcome
        .frames
        .iter()
        .filter(|frame| frame.kind == cmbl::FrameKind::Message)
        .filter_map(|frame| {
            let plain = key.unwrap(room, &frame.ciphertext)?;
            let (commit, companion) = ctnd::unpack_ordered(&plain)?;
            (!companion.is_empty()).then(|| JoinFrame {
                ordering: outcome.ordering,
                counter: frame.counter,
                commit: commit.to_vec(),
                companion: companion.to_vec(),
            })
        })
        .collect()
}

/// Marks a relayed frame as a room secret: one MLS application message sent to
/// the whole room (row 14.5). An ordered commit never starts with it: a bare MLS
/// message starts with its protocol version and a companion frame with
/// `ctnd`'s own magic.
const SECRET_MAGIC: &[u8] = b"cbrd.room.secret.v1\0";

/// One room secret read from the room: the MLS message and where it stood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretFrame {
    /// The relay sequence of the frame (a cursor for the next read).
    pub sequence: u64,
    /// The MLS application message; only Threads can open it.
    pub message: Vec<u8>,
}
/// Secrets found in one read and the relay sequence the read reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretsRead {
    pub secrets: Vec<SecretFrame>,
    pub through: u64,
}

fn secrets_in(outcome: &cmbl::Outcome, room: &cmbl::Id, key: &TransportKey) -> Vec<SecretFrame> {
    outcome
        .frames
        .iter()
        .filter(|frame| frame.kind == cmbl::FrameKind::Message)
        .filter_map(|frame| {
            let plain = key.unwrap(room, &frame.ciphertext)?;
            let message = plain.strip_prefix(SECRET_MAGIC)?;
            (!message.is_empty()).then(|| SecretFrame {
                sequence: frame.sequence,
                message: message.to_vec(),
            })
        })
        .collect()
}

/// Join requests in a read, oldest first: `(relay sequence, ephemeral key)`.
fn requests_in(outcome: &cmbl::Outcome) -> Vec<(u64, [u8; 32])> {
    outcome
        .frames
        .iter()
        .filter(|frame| frame.kind == cmbl::FrameKind::JoinRequest)
        .filter_map(|frame| Some((frame.sequence, frame.ciphertext.as_slice().try_into().ok()?)))
        .collect()
}

/// The sealed answers to request `to`, with the ordering counter each follows.
fn answers_in(
    outcome: &cmbl::Outcome,
    ordering: &cmbl::Id,
    to: u64,
) -> Result<Vec<(u64, Vec<u8>)>, Error> {
    if &outcome.ordering != ordering {
        return Err(Error::Reconcile);
    }
    Ok(outcome
        .frames
        .iter()
        .filter(|frame| frame.kind == (cmbl::FrameKind::RoomState { to }))
        .map(|frame| (frame.counter, frame.ciphertext.clone()))
        .collect())
}

fn state_operation(room: &cmbl::Id, tag: &[u8], bytes: &[u8]) -> cmbl::Id {
    let mut hash = blake3::Hasher::new();
    hash.update(b"cbrd.room.join.v1\0");
    hash.update(tag);
    hash.update(room);
    hash.update(bytes);
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    id
}

/// Time between two reads of room traffic; time stays behind a trait so the
/// library owns no timer (and nothing process-local that must survive a request).
pub trait Pause {
    fn pause(&mut self) -> PortFuture<'_, ()>;
}

/// The room's traffic as Attend needs it: the ordered member commit that
/// installs the canonical context right after the newcomer's own external
/// commit. Only the ciphertext of that one frame is returned; the room's other
/// frames are never read into the caller. Threads verifies the commit itself.
pub struct RoomFeed<'a, T, R, P> {
    board: &'a Board<T, clnk::AnonymousRooms<R>>,
    room: cmbl::Id,
    ordering: cmbl::Id,
    attempts: u8,
    pause: P,
    key: &'a TransportKey,
}
impl<'a, T: clnk::Transport, R: clnk::Transport, P: Pause> RoomFeed<'a, T, R, P> {
    /// At most `attempts` reads (at least one), `pause` between them.
    pub fn new(
        board: &'a Board<T, clnk::AnonymousRooms<R>>,
        room: cmbl::Id,
        ordering: cmbl::Id,
        attempts: u8,
        pause: P,
        key: &'a TransportKey,
    ) -> Self {
        Self {
            board,
            room,
            ordering,
            attempts: attempts.max(1),
            pause,
            key,
        }
    }
}
impl<T: clnk::Transport, R: clnk::Transport, P: Pause> cthr::ContextFeed for RoomFeed<'_, T, R, P> {
    fn context_commit<'a>(&'a mut self, after: u64) -> PortFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let wanted = after.checked_add(1).ok_or(Error::Invalid)?;
            for attempt in 0..self.attempts {
                if attempt > 0 {
                    self.pause.pause().await?;
                }
                let outcome = self
                    .board
                    .link
                    .execute_room(cmbl::Request {
                        room: self.room,
                        operation: read_operation(&self.room, after, attempt),
                        action: cmbl::Action::Read { after: 0 },
                    })
                    .await
                    .map_err(link_error)?;
                if let Some(commit) = context_frame(&outcome, &self.ordering, wanted, &self.room, self.key)? {
                    return Ok(commit);
                }
            }
            Err(Error::Unavailable)
        })
    }
}

/// Everything one member-room join needs from the device. The Board adds only
/// the room transport: the current ordering generation and counter, the Link
/// ordering of the external commit and the room traffic feed.
pub struct RoomJoinInput<'a, K, B: cwst::backend::Backend, S, A, C, P> {
    pub attend: &'a mut ctnd::Attend,
    pub member: &'a str,
    pub room: cmbl::Id,
    pub keys: &'a mut K,
    pub clock: &'a mut C,
    pub store: &'a mut cwst::Store<B>,
    /// This member's Threads for the room (no group yet).
    pub threads: &'a cthr::Threads,
    /// The prepared Groups join (consent already decided by Groups).
    pub groups: cgrp::Candidate,
    /// A current member's evidence for the group being joined.
    pub evidence: &'a cthr::ParentEvidence,
    pub source: &'a S,
    pub authority: &'a A,
    /// Encrypted to the room after the join: profile keys and the like.
    pub handover: Vec<Vec<u8>>,
    /// The signed Groups `Join` request the external commit authenticates.
    pub companion: Vec<u8>,
    pub operation: [u8; 32],
    /// Reads of room traffic while waiting for the canonical context.
    pub attempts: u8,
    pub pause: P,
    /// The room's transport key, learned from the sealed room state.
    pub transport: &'a TransportKey,
}

/// A completed join: Groups, Threads and the Attend checkpoint became visible
/// together in one durable write.
pub struct RoomJoined {
    pub committed: cthr::Committed,
    pub snapshot: cgrp::Snapshot,
    /// The encrypted hand-over outputs, already stored.
    pub handover: Vec<Vec<u8>>,
}

impl<T: clnk::Transport, R: clnk::Transport> Board<T, clnk::AnonymousRooms<R>> {
    /// Join a member room: consent (Groups), ordered external commit (Link),
    /// canonical context (room traffic), key hand-over and one atomic write
    /// through `cthr::JoinSession`. A failed attempt leaves at most the Attend
    /// `Joining` checkpoint; it is discarded and restarted, never resumed.
    pub async fn join_room<K, B, S, A, C, P>(
        &self,
        input: RoomJoinInput<'_, K, B, S, A, C, P>,
    ) -> Result<RoomJoined, Error>
    where
        K: cthr::keys::Custody,
        B: cwst::backend::Backend,
        S: cgrp::PolicySource,
        A: cgrp::Authority,
        C: ckmg::Clock,
        P: Pause,
    {
        let RoomJoinInput {
            attend,
            member,
            room,
            keys,
            clock,
            store,
            threads,
            groups,
            evidence,
            source,
            authority,
            handover,
            companion,
            operation,
            attempts,
            pause,
            transport,
        } = input;
        let now = clock.now().map_err(|_| Error::Unavailable)?;
        // Where the room's ordering stands before the external commit.
        let state = self
            .link
            .execute_room(cmbl::Request {
                room,
                operation: read_operation(&room, u64::MAX, 0),
                action: cmbl::Action::Read { after: 0 },
            })
            .await
            .map_err(link_error)?;
        let mut feed = RoomFeed::new(self, room, state.ordering, attempts, pause, transport);
        let session = cthr::JoinSession::new(cthr::JoinParts {
            keys,
            clock,
            feed: &mut feed,
            store,
            threads,
            groups,
            evidence,
            source,
            authority,
            ordering: state.ordering,
            counter: state.counter,
            handover,
            companion,
            operation,
        });
        session.begin(attend, member, room, source, now)?;
        let mut sealed_threads = session.threads();
        let mut persistence = session.persistence();
        attend
            .prepare_join(&mut sealed_threads, &mut persistence, source, now)
            .await?;
        let reply = attend
            .order(&mut RoomOrdering::new(self, transport), source, now)
            .await?;
        let outputs = attend
            .accept(&reply, &mut sealed_threads, &mut persistence, source, now)
            .await?;
        let (committed, snapshot) = session.outcome().ok_or(Error::Reconcile)?;
        Ok(RoomJoined {
            committed,
            snapshot,
            handover: outputs,
        })
    }
}

/// What a newcomer's external commit carries as its authenticated companion:
/// its signed Groups `Join` request. The newcomer's own lineage-read handle
/// rides inside the signed consent (`Consent::lineage_handle`): an admitting
/// member reads the lineage through it and believes nothing but the
/// Charter-verified record bound to the pseudonym the request names.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomCompanion {
    pub request: cgrp::Request,
}

impl RoomCompanion {
    /// The companion bytes the external commit authenticates.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let bytes = serde_json::to_vec(self).ok()?;
        (bytes.len() <= ctnd::MAX_COMPANION).then_some(bytes)
    }
    /// A companion exactly as `encode` wrote it; anything else is refused.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// Everything one admission needs from the admitting member's device. The Board
/// adds the room transport that orders the member commit.
pub struct RoomAdmitInput<'a, K, B: cwst::backend::Backend, S, A, C> {
    pub keys: &'a mut K,
    pub clock: &'a mut C,
    pub store: &'a mut cwst::Store<B>,
    /// This member's Threads for the room.
    pub threads: &'a cthr::Threads,
    /// The Groups join prepared from the newcomer's request and consent.
    pub groups: cgrp::Candidate,
    /// The newcomer's ordered external commit with its companion.
    pub frame: &'a JoinFrame,
    pub room: cmbl::Id,
    pub source: &'a S,
    pub authority: &'a A,
    pub operation: [u8; 32],
    /// The room's transport key at the epoch the newcomer joined from.
    pub transport: &'a TransportKey,
}

/// A completed admission: the member commit is ordered, and Groups and Threads
/// became visible together in one durable write.
pub struct RoomAdmitted {
    pub committed: cthr::Committed,
    pub snapshot: cgrp::Snapshot,
}

fn thread_error(error: cthr::Error) -> Error {
    match error {
        cthr::Error::Authority | cthr::Error::Scope => Error::Authority,
        cthr::Error::Conflict => Error::Reconcile,
        cthr::Error::Storage => Error::Storage,
        _ => Error::Unavailable,
    }
}

impl<T: clnk::Transport, R: clnk::Transport> Board<T, clnk::AnonymousRooms<R>> {
    /// Admit a newcomer as an existing member: authenticate its external commit
    /// against this member's exact Groups/MLS state, install the canonical
    /// context with the member commit, order that commit right after the join
    /// (the newcomer waits for it) and publish Groups and Threads in one write.
    /// Nothing is published before the member commit was ordered.
    pub async fn admit_room<K, B, S, A, C>(
        &self,
        input: RoomAdmitInput<'_, K, B, S, A, C>,
    ) -> Result<RoomAdmitted, Error>
    where
        K: cthr::keys::Custody,
        B: cwst::backend::Backend,
        S: cgrp::PolicySource,
        A: cgrp::Authority,
        C: ckmg::Clock,
    {
        let RoomAdmitInput {
            keys,
            clock,
            store,
            threads,
            groups,
            frame,
            room,
            source,
            authority,
            operation,
            transport,
        } = input;
        let (candidate, wire) = {
            let effects = groups.prepare_effects();
            let decision = effects.first().ok_or(Error::Authority)?;
            let admission = threads
                .receive_room_join(
                    keys,
                    store,
                    decision,
                    &frame.commit,
                    &frame.companion,
                    clock,
                )
                .await
                .map_err(thread_error)?;
            let candidate = admission
                .commit_context(keys, decision, clock)
                .await
                .map_err(thread_error)?;
            let wire = candidate
                .events()
                .iter()
                .find_map(|event| match event {
                    cthr::Event::MembershipCommit { bytes } => Some(bytes.clone()),
                    _ => None,
                })
                .ok_or(Error::Authority)?;
            (candidate, wire)
        };
        RoomOrdering::new(self, transport)
            .order(&ctnd::OrderRequest {
                room,
                ordering: frame.ordering,
                expected: frame.counter,
                encrypted_commit: wire,
                companion: vec![],
            })
            .await?;
        let (committed, snapshot, _) = candidate
            .commit_groups(keys, groups, store, operation, (source, authority), clock)
            .await
            .map_err(thread_error)?;
        Ok(RoomAdmitted {
            committed,
            snapshot,
        })
    }
}

/// Everything one catch-up through a completed admission needs: the newcomer's
/// ordered external commit with its companion, the member commit that installed
/// the canonical context after it, and the Groups join the companion decides.
/// Nothing is ordered or sent: the admission was made by another member and the
/// room already holds both commits.
pub struct RoomApplyInput<'a, K, B: cwst::backend::Backend, S, A, C> {
    pub keys: &'a mut K,
    pub clock: &'a mut C,
    pub store: &'a mut cwst::Store<B>,
    /// This member's Threads for the room, at the epoch the join was made for.
    pub threads: &'a cthr::Threads,
    /// The Groups join prepared from the newcomer's request and consent.
    pub groups: cgrp::Candidate,
    /// The newcomer's external commit with its companion.
    pub join: &'a OrderedCommit,
    /// The context-installing member commit that followed it.
    pub context: &'a [u8],
    pub source: &'a S,
    pub authority: &'a A,
    pub operation: [u8; 32],
}

/// Apply an admission another member already ordered: authenticate the
/// newcomer's external commit against this member's exact Groups/MLS state, then
/// the member commit that installs the canonical context, and publish Groups and
/// Threads in one write. Both commits must be made for exactly the epochs this
/// member and its successor hold (a frame of another epoch is out of order and
/// refused before anything is processed); every other check is the one
/// [`Board::admit_room`] makes, because it is the same Threads functions.
pub async fn apply_room_admission<K, B, S, A, C>(
    input: RoomApplyInput<'_, K, B, S, A, C>,
) -> Result<RoomAdmitted, Error>
where
    K: cthr::keys::Custody,
    B: cwst::backend::Backend,
    S: cgrp::PolicySource,
    A: cgrp::Authority,
    C: ckmg::Clock,
{
    let RoomApplyInput {
        keys,
        clock,
        store,
        threads,
        groups,
        join,
        context,
        source,
        authority,
        operation,
    } = input;
    let epoch = threads.epoch().map_err(thread_error)?;
    let made_for = |wire: &[u8]| cthr::wire_epoch(wire).map_err(|_| Error::Authority);
    if made_for(&join.commit)? != epoch || made_for(context)? != epoch.saturating_add(1) {
        return Err(Error::Authority);
    }
    let candidate = {
        let effects = groups.prepare_effects();
        let decision = effects.first().ok_or(Error::Authority)?;
        let admission = threads
            .receive_room_join(keys, store, decision, &join.commit, &join.companion, clock)
            .await
            .map_err(thread_error)?;
        admission
            .receive_context(keys, decision, context, clock)
            .await
            .map_err(thread_error)?
    };
    let (committed, snapshot, _) = candidate
        .commit_groups(keys, groups, store, operation, (source, authority), clock)
        .await
        .map_err(thread_error)?;
    Ok(RoomAdmitted {
        committed,
        snapshot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(ordering: cmbl::Id, counters: &[u64]) -> cmbl::Outcome {
        cmbl::Outcome {
            ordering,
            counter: counters.last().copied().unwrap_or(0),
            active_connections: 1,
            through: counters.len() as u64,
            gap: false,
            frames: counters
                .iter()
                .enumerate()
                .map(|(index, counter)| cmbl::RelayFrame {
                    kind: cmbl::FrameKind::Message,
                    sequence: index as u64 + 1,
                    counter: *counter,
                    ciphertext: TransportKey::new([3; 32], [103; 32])
                        .wrap(&[6; 16], &[index as u8])
                        .unwrap(),
                })
                .collect(),
        }
    }

    #[test]
    fn secrets_open_only_under_the_epoch_key_and_are_never_joins_or_commits() {
        let key = TransportKey::new([3; 32], [103; 32]);
        let room = [6; 16];
        let mut plain = SECRET_MAGIC.to_vec();
        plain.extend_from_slice(&[7, 7, 7]);
        let mut frames = outcome([4; 16], &[7, 7, 8]);
        frames.frames[0].ciphertext = key.wrap(&room, &plain).unwrap();
        // Another epoch's key opens nothing.
        frames.frames[1].ciphertext = TransportKey::new([4; 32], [104; 32])
            .wrap(&room, &plain)
            .unwrap();
        // A magic with nothing behind it carries no message.
        frames.frames[2].ciphertext = key.wrap(&room, SECRET_MAGIC).unwrap();
        assert_eq!(
            secrets_in(&frames, &room, &key),
            vec![SecretFrame {
                sequence: 1,
                message: vec![7, 7, 7],
            }]
        );
        // The frame is no join and is never taken for the ordered commit.
        assert_eq!(joins_in(&frames, &room, &key), vec![]);
        assert_eq!(
            context_frame(&frames, &[4; 16], 7, &room, &key).unwrap(),
            None
        );
        // An ordered commit and a secret at the same counter: the commit wins.
        frames.frames[1].ciphertext = key.wrap(&room, &[0, 1, 2]).unwrap();
        assert_eq!(
            context_frame(&frames, &[4; 16], 7, &room, &key).unwrap(),
            Some(vec![0, 1, 2])
        );
    }

    #[test]
    fn only_frames_with_a_companion_are_joins() {
        let mut room = outcome([4; 16], &[7, 8, 9]);
        let key = TransportKey::new([3; 32], [103; 32]);
        room.frames[1].ciphertext = key
            .wrap(&[6; 16], &ctnd::pack_ordered(&[0, 1, 2], &[9, 9]))
            .unwrap();
        // A malformed frame that claims the companion magic is never a join.
        let mut broken = ctnd::pack_ordered(&[0, 1, 2], &[9]);
        broken.pop();
        room.frames[2].ciphertext = key.wrap(&[6; 16], &broken).unwrap();
        // The relay sees only ciphertext: a plain companion frame is no join.
        assert_eq!(
            joins_in(&room, &[6; 16], &TransportKey::new([4; 32], [104; 32])),
            vec![]
        );
        assert_eq!(
            joins_in(&room, &[6; 16], &key),
            vec![JoinFrame {
                ordering: [4; 16],
                counter: 8,
                commit: vec![0, 1, 2],
                companion: vec![9, 9],
            }]
        );
    }

    #[test]
    fn the_first_frame_at_the_wanted_counter_is_the_context_commit() {
        // Frame 0 is the newcomer's own commit (counter 7); a relayed frame
        // at 7 follows; the ordered context commit is the first frame at 8.
        let room = outcome([1; 16], &[7, 7, 8, 8]);
        assert_eq!(context_frame(&room, &[1; 16], 8, &[6; 16], &TransportKey::new([3; 32], [103; 32])), Ok(Some(vec![2])));
        assert_eq!(context_frame(&room, &[1; 16], 9, &[6; 16], &TransportKey::new([3; 32], [103; 32])), Ok(None));
    }

    #[test]
    fn another_ordering_generation_is_a_reconcile_not_a_commit() {
        let room = outcome([2; 16], &[8]);
        assert_eq!(context_frame(&room, &[1; 16], 8, &[6; 16], &TransportKey::new([3; 32], [103; 32])), Err(Error::Reconcile));
    }

    #[test]
    fn the_context_commit_is_never_a_room_state_frame() {
        let mut room = outcome([1; 16], &[8, 8]);
        room.frames[0].kind = cmbl::FrameKind::RoomState { to: 1 };
        assert_eq!(context_frame(&room, &[1; 16], 8, &[6; 16], &TransportKey::new([3; 32], [103; 32])), Ok(Some(vec![1])));
    }

    #[test]
    fn requests_and_their_answers_are_picked_by_kind_and_target() {
        let mut room = outcome([1; 16], &[7, 7, 8, 8]);
        room.frames[0].kind = cmbl::FrameKind::JoinRequest;
        room.frames[0].ciphertext = vec![5; 32];
        room.frames[1].kind = cmbl::FrameKind::JoinRequest; // wrong length: ignored
        room.frames[2].kind = cmbl::FrameKind::RoomState { to: 1 };
        room.frames[3].kind = cmbl::FrameKind::RoomState { to: 2 };
        assert_eq!(requests_in(&room), vec![(1, [5; 32])]);
        // Sealed room state is its own envelope, not a transport frame: returned untouched.
        assert_eq!(
            answers_in(&room, &[1; 16], 1),
            Ok(vec![(8, room.frames[2].ciphertext.clone())])
        );
        assert_eq!(answers_in(&room, &[1; 16], 9), Ok(vec![]));
        assert_eq!(answers_in(&room, &[9; 16], 1), Err(Error::Reconcile));
    }

    #[test]
    fn room_frames_keep_only_member_traffic_and_carry_the_relays_gap_flag() {
        let mut room = outcome([4; 16], &[7, 7, 8, 9]);
        room.frames[1].kind = cmbl::FrameKind::JoinRequest;
        room.frames[2].kind = cmbl::FrameKind::RoomState { to: 1 };
        room.gap = true;
        let frames = room_frames_in(&room);
        assert_eq!(frames.ordering, [4; 16]);
        assert!(frames.gap);
        assert_eq!(
            frames
                .frames
                .iter()
                .map(|frame| (frame.sequence, frame.counter))
                .collect::<Vec<_>>(),
            vec![(1, 7), (4, 9)]
        );
        room.gap = false;
        assert!(!room_frames_in(&room).gap);
    }

    #[test]
    fn a_frame_opens_as_a_commit_or_a_secret_only_under_its_own_epochs_key() {
        let room = [6; 16];
        let (key, next) = (
            TransportKey::new([3; 32], [103; 32]),
            TransportKey::new([4; 32], [104; 32]),
        );
        let mut secret = SECRET_MAGIC.to_vec();
        secret.extend_from_slice(&[7, 7]);
        let mut frames = outcome([4; 16], &[7, 7, 8, 8]);
        frames.frames[0].ciphertext = key
            .wrap(&room, &ctnd::pack_ordered(&[1, 2, 3], &[9, 9]))
            .unwrap();
        frames.frames[1].ciphertext = key.wrap(&room, &secret).unwrap();
        // The member commit of the next epoch is sealed under the next key.
        frames.frames[2].ciphertext = next
            .wrap(&room, &ctnd::pack_ordered(&[4, 5, 6], &[]))
            .unwrap();
        frames.frames[3].ciphertext = vec![0; 40];
        let read = room_frames_in(&frames);
        assert_eq!(
            read.frames[0].open(&room, &key),
            Some(FrameContent::Commit(OrderedCommit {
                commit: vec![1, 2, 3],
                companion: vec![9, 9],
            }))
        );
        assert_eq!(read.frames[1].open(&room, &key), Some(FrameContent::Secret));
        // A member that stayed in the old epoch (a removed member holds nothing
        // else) opens nothing of the next epoch, and the next epoch's key opens
        // nothing of the old one; junk opens under no key.
        assert_eq!(read.frames[2].open(&room, &key), None);
        assert_eq!(read.frames[0].open(&room, &next), None);
        assert_eq!(read.frames[1].open(&room, &next), None);
        assert_eq!(read.frames[3].open(&room, &key), None);
        assert_eq!(
            read.frames[2].open(&room, &next),
            Some(FrameContent::Commit(OrderedCommit {
                commit: vec![4, 5, 6],
                companion: vec![],
            }))
        );
        // The same ciphertext is another room's noise.
        assert_eq!(read.frames[0].open(&[7; 16], &key), None);
    }
}
