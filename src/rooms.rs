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
                    ciphertext: request.encrypted_commit.clone(),
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
        .find(|frame| frame.counter == wanted)
        .map(|frame| frame.ciphertext.clone()))
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
                    sequence: index as u64 + 1,
                    counter: *counter,
                    ciphertext: vec![index as u8],
                })
                .collect(),
        }
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
}
