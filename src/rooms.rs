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
