//! Current original-owner inputs for reads after a network await.
use crate::{Board, Discovery, Error, Input, Page, PendingCiphertext, PendingSearch, PendingWatch};

/// Trusted deployment policy, never selected by a public action or publication.
/// No default action or acceptable snapshot age is inferred.
pub struct ReadPolicy<'a> {
    pub admission_action: &'a str,
    /// Maximum signed snapshot age in Unix seconds, passed to original Charter.
    pub maximum_snapshot_age: u64,
}

/// Borrow these owners anew after each external await. The runtime must first
/// reconcile actual Vault/Keys checkpoint freshness and current device authority.
/// `binding` comes from those current Keys, and `charter` from the ONE Foyer trust
/// consumer. This context neither grants G3 nor proves remote G2 currentness.
/// Hold the actual Store guard throughout the synchronous finish/read operation.
/// No policy, publication bytes, revision floor or success boolean is accepted.
pub struct ReadContext<'a, B: cwst::backend::Backend> {
    pub store: &'a cwst::Store<B>,
    pub binding: &'a ckmg::Binding,
    pub charter: &'a cchr::VerifiedCharter,
    pub policy: ReadPolicy<'a>,
    pub contact: &'a dyn Fn(&str) -> cshm::ContactCheck,
}

impl<T: clnk::Transport, R> Board<T, R> {
    /// Consume an undisclosed response using the exact committed local Profile
    /// and freshly borrowed Charter. Policy construction stays inside Board.
    pub fn finish_search_committed<B: cwst::backend::Backend>(
        &mut self,
        pending: PendingSearch,
        context: &ReadContext<'_, B>,
    ) -> Result<Page, Error> {
        let contact = |text: &str| (context.contact)(text);
        self.with_committed(context, |board, own, verification| {
            board.finish_search(pending, own, verification, &contact)
        })
    }

    /// Revalidate the same bounded polling window using current original owners.
    pub fn finish_watch_committed<B: cwst::backend::Backend>(
        &mut self,
        pending: PendingWatch,
        context: &ReadContext<'_, B>,
    ) -> Result<Page, Error> {
        let contact = |text: &str| (context.contact)(text);
        self.with_committed(context, |board, own, verification| {
            board.finish_watch(pending, own, verification, &contact)
        })
    }

    /// The remote candidate remains an untrusted original publication. Search
    /// checks both directions and the existing finisher binds its exact envelope.
    pub fn finish_ciphertext_committed<B: cwst::backend::Backend>(
        &mut self,
        pending: PendingCiphertext,
        peer: Input<'_>,
        context: &ReadContext<'_, B>,
    ) -> Result<Vec<u8>, Error> {
        let contact = |text: &str| (context.contact)(text);
        self.with_committed(context, |board, own, verification| {
            board.finish_ciphertext(pending, (own, peer), verification, &contact)
        })
    }

    /// Recheck immediately before every display. A previously returned DTO is
    /// data only; it never retains authority across local or remote changes.
    pub fn read_discovery_committed<B: cwst::backend::Backend>(
        &mut self,
        context: &ReadContext<'_, B>,
    ) -> Result<Vec<Discovery>, Error> {
        let contact = |text: &str| (context.contact)(text);
        self.with_committed(context, |board, own, verification| {
            board.read_discovery(own, verification, &contact)
        })
    }

    /// Local group views from the committed Groups checkpoint under the policy
    /// projected from the freshly borrowed Charter's signed settings. Read-only:
    /// no consent, membership or network operation, and no Forum traffic.
    pub fn read_groups_committed<B: cwst::backend::Backend>(
        &self,
        context: &ReadContext<'_, B>,
    ) -> Result<Vec<cgrp::GroupView>, Error> {
        if context.binding.community() != self.community
            || context.charter.community() != self.community
            || !context.store.is_scope(&self.community)
        {
            return Err(Error::Scope);
        }
        let now = self.link.now_ms().map_err(|_| Error::Unavailable)? / 1000;
        let settings = context
            .charter
            .settings(now)
            .map_err(|_| Error::Unavailable)?;
        let source = crate::SettingsPolicy::new(settings, context.charter.valid_until());
        let policy = cgrp::PolicySource::current(&source, &self.community, now)
            .map_err(|_| Error::Rejected)?;
        cgrp::Snapshot::load(&self.community, context.store)
            .and_then(|snapshot| snapshot.views(&policy, now))
            .map_err(|_| Error::Rejected)
    }

    fn with_committed<B: cwst::backend::Backend, O>(
        &mut self,
        context: &ReadContext<'_, B>,
        read: impl FnOnce(&mut Self, Input<'_>, &crate::Verification<'_>) -> Result<O, Error>,
    ) -> Result<O, Error> {
        let result = (|| {
            if context.binding.community() != self.community
                || context.charter.community() != self.community
            {
                return Err(Error::Scope);
            }
            if context.policy.admission_action.is_empty()
                || context.policy.maximum_snapshot_age == 0
            {
                return Err(Error::Rejected);
            }
            let now = self.link.now_ms().map_err(|_| Error::Unavailable)? / 1000;
            let current_policy = || {
                context
                    .charter
                    .admission_policy(
                        context.policy.admission_action,
                        now,
                        context.policy.maximum_snapshot_age,
                    )
                    .map_err(|_| Error::Rejected)
            };
            let signed_schema = context
                .charter
                .publication(cchr::Kind::Schema)
                .signed_bytes();
            let publication = cpfl::load_current_committed(
                context.store,
                context.binding,
                cpfl::Validation {
                    policy: current_policy()?,
                    signed_schema,
                    contact: context.contact,
                },
            )
            .map_err(|_| Error::Rejected)?
            .ok_or(Error::Unavailable)?;
            let policy = current_policy()?;
            let verification = crate::Verification {
                policy: &policy,
                signed_schema,
            };
            let transcript = publication.verified().transcript();
            let own = Input {
                member: &transcript.member,
                minimum_revision: transcript.revision,
                bytes: publication.bytes(),
            };
            let output = read(self, own, &verification)?;
            // Synchronous owner checks can also cross a clock boundary. Never
            // return the result with a policy evaluated in an earlier second.
            self.current_verification(&verification)?;
            self.own_publication(own)?;
            Ok(output)
        })();
        if result.is_err() {
            self.clear_view();
        }
        result
    }
}
