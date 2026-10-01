//! Same-community device Board composition. All authority and domain transitions
//! stay with the leaf owners; the sole Forum connection is Link.
pub use cgrp::GroupView;
pub use ctnd::Phase as RoomPhase;
use schemars::JsonSchema;
use serde::Serialize;

/// Facade failures contain no profile values or owner internals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    /// Configuration or owner context belongs to another community.
    Scope,
    /// Required live/transaction integration is not available.
    Unavailable,
    /// A real leaf owner rejected the supplied local input.
    Rejected,
}
/// Availability of an owner that does not yet have a runtime adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Unavailable,
}
/// Read-only derived status, never caller-supplied presence or group authority.
#[derive(Clone, Serialize, JsonSchema)]
pub struct Status {
    /// Actual Link lifecycle; it has no fabricated Present state.
    pub connection: clnk::State,
    /// Shared Groups/Vault transaction adapter status.
    pub groups: Availability,
    /// Current MLS/ordering/anonymous-pass adapter status.
    pub rooms: Availability,
}

/// A Board has a fixed local community and exactly one Link. It owns no copy of
/// Contacts, the profile draft, the wallet or the server search index.
pub struct Board<T, R = ()> {
    community: String,
    link: clnk::Link<T, R>,
}
impl<T: clnk::Transport, R> Board<T, R> {
    /// Bind one runtime's existing Link; this neither authenticates nor connects.
    pub fn new(community: String, link: clnk::Link<T, R>) -> Result<Self, Error> {
        if community.is_empty() || community.len() > 256 {
            return Err(Error::Scope);
        }
        Ok(Self { community, link })
    }
    /// Current local namespace, fixed independently of public action bodies.
    pub fn community(&self) -> &str {
        &self.community
    }
    /// Reflect child state without treating reachable transports as admission.
    pub fn status(&self) -> Status {
        Status {
            connection: self.link.state(),
            groups: Availability::Unavailable,
            rooms: Availability::Unavailable,
        }
    }
    /// The generated Forum challenge through this Board's sole Link.
    pub async fn connect(
        &mut self,
        input: clnk::ChallengeInput,
    ) -> Result<std::convert::Infallible, clnk::ErrorCode> {
        self.link.connect(input).await
    }
    /// Clear live Link state. Pending durable owners still require reconciliation.
    pub fn disconnect(&mut self) {
        self.link.disconnect();
    }
    /// Local public-pair validation, not current forum disclosure authority.
    pub fn recheck(
        &self,
        requester: csrh::Input<'_>,
        owner: csrh::Input<'_>,
        verification: &csrh::Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<csrh::CheckedPair, Error> {
        self.scope(verification)?;
        csrh::recheck(requester, owner, verification, contact).map_err(|_| Error::Rejected)
    }
    /// Give-first local inspection. No external notice or key release occurs.
    pub fn inspect(
        &self,
        offer: &cxch::Offer,
        inputs: (csrh::Input<'_>, csrh::Input<'_>),
        verification: &csrh::Verification<'_>,
        key: cnvl::ReadKey,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<cxch::Inspection, Error> {
        self.scope(verification)?;
        cxch::inspect(offer, inputs.0, inputs.1, verification, key, contact)
            .map_err(|_| Error::Rejected)
    }
    fn scope(&self, verification: &csrh::Verification<'_>) -> Result<(), Error> {
        if verification.policy.policy.community != self.community {
            return Err(Error::Scope);
        }
        Ok(())
    }
}
