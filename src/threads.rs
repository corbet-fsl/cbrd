//! Member rooms: `ctnd::Threads` over cthr. The device joins the room's MLS
//! group by an external commit (ordered through Link by Attend), then waits for
//! the member commit that installs the canonical Groups context, and seals its
//! hand-over (profile keys) to the room. Everything here is MLS evidence; the
//! consent, the Groups decision and the single owner checkpoint stay with the
//! caller, and no MLS or crypto is implemented in this file.
//!
//! The leaf credential is cthr's per-community scoped certificate only; the
//! tests of cthr assert its exact content. The external commit is an MLS
//! PublicMessage (RFC 9420), so the ordering server sees that pseudonymous
//! leaf, never a global or device-stable identity or any plaintext.
use cgrp::{Effect, PolicySource, PreparedEffect};
use cthr::keys::Custody;
use ctnd::{Error, OrderReply, OrderRequest, OrderedJoin, PortFuture, PreparedJoin};

/// The ordered member commit that installs the canonical context. Whoever
/// receives room traffic implements it; a member commit arrives only after the
/// newcomer's external commit holding `after` was ordered.
pub trait ContextFeed {
    fn context_commit<'a>(&'a mut self, after: u64) -> PortFuture<'a, Vec<u8>>;
}

fn map(error: cthr::Error) -> Error {
    match error {
        cthr::Error::Authority | cthr::Error::Scope => Error::Authority,
        cthr::Error::Conflict => Error::Reconcile,
        cthr::Error::Storage => Error::Storage,
        _ => Error::Unavailable,
    }
}

/// One join attempt. A fresh value is made per attempt: a lost attempt is
/// discarded, never resumed, so Threads never produces a second external
/// commit for the same prepared join.
pub struct RoomThreads<'a, K, S, C, F> {
    keys: &'a mut K,
    threads: &'a cthr::Threads,
    decision: &'a PreparedEffect<'a>,
    evidence: &'a cthr::ParentEvidence,
    source: &'a S,
    clock: &'a mut C,
    feed: &'a mut F,
    ordering: [u8; 16],
    counter: u64,
    handover: Vec<Vec<u8>>,
    prepared: Option<(cthr::RoomJoin, u64)>,
    finished: Option<cthr::Candidate>,
}

/// What the caller supplies for one attempt.
pub struct Attempt<'a, K, S, C, F> {
    pub keys: &'a mut K,
    pub threads: &'a cthr::Threads,
    pub decision: &'a PreparedEffect<'a>,
    pub evidence: &'a cthr::ParentEvidence,
    pub source: &'a S,
    pub clock: &'a mut C,
    pub feed: &'a mut F,
    /// Assembly's current ordering generation and join counter for the room.
    pub ordering: [u8; 16],
    pub counter: u64,
    /// Encrypted to the room after the join: profile keys and the like.
    pub handover: Vec<Vec<u8>>,
}

impl<'a, K, S, C, F> RoomThreads<'a, K, S, C, F> {
    pub fn new(attempt: Attempt<'a, K, S, C, F>) -> Self {
        Self {
            keys: attempt.keys,
            threads: attempt.threads,
            decision: attempt.decision,
            evidence: attempt.evidence,
            source: attempt.source,
            clock: attempt.clock,
            feed: attempt.feed,
            ordering: attempt.ordering,
            counter: attempt.counter,
            handover: attempt.handover,
            prepared: None,
            finished: None,
        }
    }

    /// The joined MLS candidate for the one owner transaction with the matching
    /// Groups candidate. Available only after the order was accepted.
    pub fn take_candidate(&mut self) -> Option<cthr::Candidate> {
        self.finished.take()
    }
}

impl<K, S, C, F> ctnd::Threads for RoomThreads<'_, K, S, C, F>
where
    K: Custody,
    S: PolicySource,
    C: ckmg::Clock,
    F: ContextFeed,
{
    fn prepare<'a>(
        &'a mut self,
        group: &'a [u8; 32],
        membership_revision: u64,
    ) -> PortFuture<'a, PreparedJoin> {
        Box::pin(async move {
            let Effect::Membership {
                group: decided,
                revision,
                ..
            } = self.decision.event()
            else {
                return Err(Error::Authority);
            };
            if decided != group || *revision != membership_revision || self.prepared.is_some() {
                return Err(Error::Authority);
            }
            let join = self
                .threads
                .prepare_room_join(
                    &mut *self.keys,
                    self.decision,
                    self.evidence,
                    self.source,
                    &mut *self.clock,
                )
                .await
                .map_err(map)?;
            let prepared = PreparedJoin::new(
                self.ordering,
                self.counter,
                join.commit().to_vec(),
                join.epoch(),
            )?;
            let epoch = join.epoch();
            self.prepared = Some((join, epoch));
            Ok(prepared)
        })
    }

    fn verify_order<'a>(
        &'a mut self,
        request: &'a OrderRequest,
        reply: &'a OrderReply,
    ) -> PortFuture<'a, OrderedJoin> {
        Box::pin(async move {
            let (join, epoch) = self.prepared.take().ok_or(Error::Invalid)?;
            if request.encrypted_commit != join.commit()
                || reply.ordering != self.ordering
                || request.ordering != self.ordering
                || self.counter.checked_add(1) != Some(reply.counter)
            {
                return Err(Error::Reconcile);
            }
            let context = self.feed.context_commit(reply.counter).await?;
            let (candidate, sealed) = join
                .finish(
                    &mut *self.keys,
                    self.decision,
                    &context,
                    &self.handover,
                    &mut *self.clock,
                )
                .await
                .map_err(map)?;
            let ordered = OrderedJoin::new(self.ordering, reply.counter, epoch, sealed)?;
            self.finished = Some(candidate);
            Ok(ordered)
        })
    }
}
