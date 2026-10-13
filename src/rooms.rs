//! Member rooms through Attend: Link ordering for the join, and the "here now"
//! count. Consent is a Groups join with the semipublic statement; MLS and the
//! key hand-over belong to Threads behind `ctnd::Threads`. Members see only how
//! many connections are present, never traffic volume or identities.
use crate::Board;
use clnk::cmbl;
use ctnd::{Error, Link, OrderReply, OrderRequest, PortFuture};

fn operation(request: &OrderRequest) -> cmbl::Id {
    // Deterministic, so an exact retry of the same order reaches Assembly's
    // original operation receipt instead of applying the commit twice.
    let mut hash = blake3::Hasher::new();
    hash.update(b"cbrd.room.order.v1\0");
    hash.update(&request.room);
    hash.update(&request.ordering);
    hash.update(&request.expected.to_be_bytes());
    hash.update(&request.encrypted_commit);
    hash.update(&request.companion);
    let mut id = [0; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    id
}

/// The one Link implementation for Attend: orders an encrypted commit through
/// the Board's anonymous room transport. A refusal after the request may have
/// reached the room is `Reconcile`, never a retry instruction.
pub struct RoomOrdering<'a, T, R> {
    board: &'a Board<T, clnk::AnonymousRooms<R>>,
}
impl<'a, T: clnk::Transport, R: clnk::Transport> RoomOrdering<'a, T, R> {
    pub fn new(board: &'a Board<T, clnk::AnonymousRooms<R>>) -> Self {
        Self { board }
    }
}
impl<T: clnk::Transport, R: clnk::Transport> Link for RoomOrdering<'_, T, R> {
    fn order<'a>(&'a mut self, request: &'a OrderRequest) -> PortFuture<'a, OrderReply> {
        Box::pin(async move {
            let command = cmbl::Request {
                room: request.room,
                operation: operation(request),
                action: cmbl::Action::Order {
                    expected: request.expected,
                    ciphertext: ctnd::pack_ordered(&request.encrypted_commit, &request.companion),
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
            joins: joins_in(&outcome),
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
) -> Result<Option<Vec<u8>>, Error> {
    if &outcome.ordering != ordering {
        return Err(Error::Reconcile);
    }
    Ok(outcome
        .frames
        .iter()
        .find(|frame| frame.kind == cmbl::FrameKind::Message && frame.counter == wanted)
        .map(|frame| frame.ciphertext.clone()))
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

fn joins_in(outcome: &cmbl::Outcome) -> Vec<JoinFrame> {
    outcome
        .frames
        .iter()
        .filter(|frame| frame.kind == cmbl::FrameKind::Message)
        .filter_map(|frame| {
            let (commit, companion) = ctnd::unpack_ordered(&frame.ciphertext)?;
            (!companion.is_empty()).then(|| JoinFrame {
                ordering: outcome.ordering,
                counter: frame.counter,
                commit: commit.to_vec(),
                companion: companion.to_vec(),
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
}
impl<'a, T: clnk::Transport, R: clnk::Transport, P: Pause> RoomFeed<'a, T, R, P> {
    /// At most `attempts` reads (at least one), `pause` between them.
    pub fn new(
        board: &'a Board<T, clnk::AnonymousRooms<R>>,
        room: cmbl::Id,
        ordering: cmbl::Id,
        attempts: u8,
        pause: P,
    ) -> Self {
        Self {
            board,
            room,
            ordering,
            attempts: attempts.max(1),
            pause,
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
                if let Some(commit) = context_frame(&outcome, &self.ordering, wanted)? {
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
        let mut feed = RoomFeed::new(self, room, state.ordering, attempts, pause);
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
            .order(&mut RoomOrdering::new(self), source, now)
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
                    ciphertext: vec![index as u8],
                })
                .collect(),
        }
    }

    #[test]
    fn only_frames_with_a_companion_are_joins() {
        let mut room = outcome([4; 16], &[7, 8, 9]);
        room.frames[1].ciphertext = ctnd::pack_ordered(&[0, 1, 2], &[9, 9]);
        // A malformed frame that claims the companion magic is never a join.
        let mut broken = ctnd::pack_ordered(&[0, 1, 2], &[9]);
        broken.pop();
        room.frames[2].ciphertext = broken;
        assert_eq!(
            joins_in(&room),
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
        assert_eq!(context_frame(&room, &[1; 16], 8), Ok(Some(vec![2])));
        assert_eq!(context_frame(&room, &[1; 16], 9), Ok(None));
    }

    #[test]
    fn another_ordering_generation_is_a_reconcile_not_a_commit() {
        let room = outcome([2; 16], &[8]);
        assert_eq!(context_frame(&room, &[1; 16], 8), Err(Error::Reconcile));
    }

    #[test]
    fn the_context_commit_is_never_a_room_state_frame() {
        let mut room = outcome([1; 16], &[8, 8]);
        room.frames[0].kind = cmbl::FrameKind::RoomState { to: 1 };
        assert_eq!(context_frame(&room, &[1; 16], 8), Ok(Some(vec![1])));
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
        assert_eq!(answers_in(&room, &[1; 16], 1), Ok(vec![(8, vec![2])]));
        assert_eq!(answers_in(&room, &[1; 16], 9), Ok(vec![]));
        assert_eq!(answers_in(&room, &[9; 16], 1), Err(Error::Reconcile));
    }
}
