//! Same-community device Board composition. All authority and domain transitions
//! stay with the leaf owners; the sole Forum connection is Link.
#![forbid(unsafe_code)]
mod authority;
mod committed;
mod exchange;
mod group_invite;
mod groups;
pub mod join_seal;
mod policy;
mod profile;
mod rooms;
pub use authority::{BoardAuthority, Contacts, Devices, Seeds};
pub use cgrd;
pub use cgrp::{self, GroupView};
pub use clnk::{self, Challenge, Prepared, cfrm};
pub use committed::{ReadContext, ReadPolicy};
pub use crbk;
pub use csrh::{Discovery, Input, Verification, ViewLimits};
/// Attend's Threads and single-owner-transaction ports for a member room join
/// live with the MLS owner in cthr (tests with real MLS, Groups and Storage).
pub use cthr::{ContextFeed, JoinParts, JoinSession};
pub use exchange::{
    Answer, ExchangeContext, MAX_MESSAGE_BYTES, Notice, Opened, PEER_KEY_OWNER, Reply, Request,
    peer_key_slot,
};
pub use group_invite::{
    Committed as GroupCommitted, INVITE_VERSION, Invitation, Message as GroupMessage,
    Proposal as GroupProposal, commit as commit_group_proposal, propose as propose_group_command,
};
pub use groups::{
    CONSENT_SECONDS, GroupOwner, Intent as GroupIntent, PolicyAt, PortFuture, Published, Signed,
    command_members, created_group, execute as execute_group_command,
    execute_intent as execute_group_intent, prepare_command as prepare_group_command,
    prepare_intent as prepare_group_intent, required_consents,
};
pub use policy::{SettingsPolicy, project as project_group_policy};
pub use profile::{Edit, PublishContext, block_rules, commit_profile};
pub use rooms::{
    JoinFrame, JoinsRead, Pause, RoomAdmitInput, RoomAdmitted, RoomCompanion, RoomFeed,
    RoomJoinInput, RoomJoined, RoomOrdering,
};
pub use {cnvl, cpfl, cshm};
/// A bounded locally rechecked page; original owner types carry its evidence.
pub struct Page {
    pub pairs: Vec<csrh::CheckedPair>,
    pub cursor: Option<Vec<u8>>,
    pub watch: Vec<u8>,
}

/// Undisclosed network output. Rebuild current Charter/Guard and reload the
/// committed own publication after the await, then consume with finish_search.
/// This type has no serializer or content accessor.
pub struct PendingSearch {
    page: cfrm::SearchOutput,
    requester: Vec<u8>,
}
/// Undisclosed ciphertext, bound to the exact original requested owner/revision.
pub struct PendingWatch {
    delta: cfrm::WatchOutput,
    requester: Vec<u8>,
    base: Vec<u8>,
}
pub struct PendingCiphertext {
    bytes: Vec<u8>,
    requester: Vec<u8>,
    owner: Vec<u8>,
    revision: Vec<u8>,
}

/// Canonical frontend projection of a freshly checked page. No original signed
/// publication, private capability, rule or remote refusal is serialized.
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct DiscoveryPage {
    pub entries: Vec<Discovery>,
    pub cursor: Option<Vec<u8>>,
    pub watch: Vec<u8>,
}
impl Page {
    pub fn discovery(&self) -> DiscoveryPage {
        DiscoveryPage {
            entries: self
                .pairs
                .iter()
                .filter_map(|pair| pair.discovery())
                .collect(),
            cursor: self.cursor.clone(),
            watch: self.watch.clone(),
        }
    }
}
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
    /// Actual Link lifecycle, derived from the current owner session and clock.
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
    search: Option<csrh::View>,
    watch: Option<Vec<u8>>,
}
impl<T: clnk::Transport, R> Board<T, R> {
    /// Original signed Forum settings for the cmsg runtime's Charter verification
    /// and maintained Rulebook minimum-version decision, before member work.
    pub async fn settings(&self) -> Result<cfrm::SettingsOutput, clnk::ErrorCode> {
        self.link.settings().await
    }
    /// Bind one runtime's existing Link; this neither authenticates nor connects.
    pub fn new(community: String, link: clnk::Link<T, R>) -> Result<Self, Error> {
        if community.is_empty()
            || community.len() > 256
            || link.community().is_some_and(|scope| scope != community)
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            community,
            link,
            search: None,
            watch: None,
        })
    }
    pub fn with_search(mut self, limits: ViewLimits) -> Result<Self, Error> {
        self.search = Some(csrh::View::new(limits).map_err(|_| Error::Rejected)?);
        Ok(self)
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
    ) -> Result<clnk::Challenge, clnk::ErrorCode> {
        self.clear_view();
        self.link.connect(input).await
    }
    pub async fn enter(&mut self, signature: Vec<u8>) -> Result<(), clnk::ErrorCode> {
        self.clear_view();
        self.link.enter(signature).await
    }
    pub fn prepare(
        &self,
        request: cfrm::Request,
        nonce: [u8; 16],
    ) -> Result<Prepared, clnk::ErrorCode> {
        self.link.prepare(request, nonce)
    }
    /// Domain reads use `search` and current local checks below. Mutations clear
    /// the displayed page before dispatch, including a queued block or departure.
    pub async fn execute(
        &mut self,
        prepared: Prepared,
        signature: Vec<u8>,
    ) -> Result<cfrm::Reply, clnk::ErrorCode> {
        if matches!(prepared.action(), "search" | "watch" | "ciphertext") {
            return Err(clnk::ErrorCode::InvalidRequest);
        }
        self.clear_view();
        self.link.execute(prepared, signature).await
    }
    /// Compatibility convenience for a request completing in the same trusted
    /// clock second. Use receive/finish when rebuilding authority after an await.
    pub async fn search(
        &mut self,
        prepared: Prepared,
        signature: Vec<u8>,
        requester: Input<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Page, Error> {
        self.current_verification(verification)?;
        self.own_publication(requester)?;
        let pending = self.receive_search(prepared, signature).await?;
        self.finish_search(pending, requester, verification, contact)
    }
    pub async fn receive_search(
        &mut self,
        prepared: Prepared,
        signature: Vec<u8>,
    ) -> Result<PendingSearch, Error> {
        self.clear_view();
        if prepared.action() != "search" {
            return Err(Error::Rejected);
        }
        let requester = self.link.publication().ok_or(Error::Rejected)?;
        let reply = self
            .link
            .execute(prepared, signature)
            .await
            .map_err(|_| Error::Rejected)?;
        let cfrm::Output::Search(page) = reply.response else {
            return Err(Error::Rejected);
        };
        if self.link.publication().as_ref() != Some(&requester) {
            return Err(Error::Rejected);
        }
        Ok(PendingSearch { page, requester })
    }
    pub fn finish_search(
        &mut self,
        pending: PendingSearch,
        requester: Input<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Page, Error> {
        self.clear_view();
        self.current_verification(verification)?;
        self.own_publication(requester)?;
        if requester.bytes != pending.requester {
            return Err(Error::Rejected);
        }
        let page = pending.page;
        let members: Vec<&str> = page
            .entries
            .iter()
            .map(|entry| std::str::from_utf8(&entry.owner).map_err(|_| Error::Rejected))
            .collect::<Result<_, _>>()?;
        let inputs: Vec<_> = page
            .entries
            .iter()
            .zip(members)
            .map(|(entry, member)| Input {
                member,
                minimum_revision: entry.revision,
                bytes: &entry.publication,
            })
            .collect();
        let view = self.search.as_mut().ok_or(Error::Unavailable)?;
        view.replace(requester, &inputs, verification, contact)
            .map_err(|_| Error::Rejected)?;
        let pairs = view
            .read(requester, verification, contact)
            .map_err(|_| Error::Rejected)?;
        self.watch = Some(page.watch.clone());
        Ok(Page {
            pairs,
            cursor: page.cursor,
            watch: page.watch,
        })
    }
    /// Fetch an undisclosed delta for exactly the held bounded page. Rebuild
    /// current policy after the await, then finish_watch before any display.
    pub async fn receive_watch(
        &mut self,
        prepared: Prepared,
        signature: Vec<u8>,
    ) -> Result<PendingWatch, Error> {
        let cfrm::Request::Watch(input) = prepared.request() else {
            return Err(Error::Rejected);
        };
        if self.watch.as_ref() != Some(&input.cursor) {
            return Err(Error::Rejected);
        }
        let base = input.cursor.clone();
        let requester = self.link.publication().ok_or(Error::Rejected)?;
        let reply = match self.link.execute(prepared, signature).await {
            Ok(reply) => reply,
            Err(_) => {
                self.clear_view();
                return Err(Error::Rejected);
            }
        };
        let cfrm::Output::Watch(delta) = reply.response else {
            self.clear_view();
            return Err(Error::Rejected);
        };
        if self.link.publication().as_ref() != Some(&requester) {
            self.clear_view();
            return Err(Error::Rejected);
        }
        Ok(PendingWatch {
            delta,
            requester,
            base,
        })
    }
    pub fn finish_watch(
        &mut self,
        pending: PendingWatch,
        requester: Input<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Page, Error> {
        let result = self.apply_watch(pending, requester, verification, contact);
        if result.is_err() {
            self.clear_view();
        }
        result
    }
    fn apply_watch(
        &mut self,
        pending: PendingWatch,
        requester: Input<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Page, Error> {
        self.current_verification(verification)?;
        self.own_publication(requester)?;
        if self.watch.as_ref() != Some(&pending.base) || requester.bytes != pending.requester {
            return Err(Error::Rejected);
        }
        let delta = pending.delta;
        let members: Vec<_> = delta
            .upserts
            .iter()
            .map(|entry| std::str::from_utf8(&entry.owner).map_err(|_| Error::Rejected))
            .collect::<Result<_, _>>()?;
        let upserts: Vec<_> = delta
            .upserts
            .iter()
            .zip(members)
            .map(|(entry, member)| Input {
                member,
                minimum_revision: entry.revision,
                bytes: &entry.publication,
            })
            .collect();
        let removed: Vec<_> = delta
            .removed
            .iter()
            .map(|member| std::str::from_utf8(member).map_err(|_| Error::Rejected))
            .collect::<Result<_, _>>()?;
        let view = self.search.as_mut().ok_or(Error::Unavailable)?;
        view.delta(requester, &upserts, &removed, verification, contact)
            .map_err(|_| Error::Rejected)?;
        let pairs = view
            .read(requester, verification, contact)
            .map_err(|_| Error::Rejected)?;
        self.watch = Some(delta.watch.clone());
        Ok(Page {
            pairs,
            cursor: delta.cursor,
            watch: delta.watch,
        })
    }

    /// Fetch only the exact candidate whose original publication passes the
    /// current local two-way check; Link still supplies actual server authority.
    pub async fn ciphertext(
        &mut self,
        prepared: Prepared,
        signature: Vec<u8>,
        inputs: (Input<'_>, Input<'_>),
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<u8>, Error> {
        self.current_verification(verification)?;
        self.own_publication(inputs.0)?;
        let pending = self.receive_ciphertext(prepared, signature).await?;
        self.finish_ciphertext(pending, inputs, verification, contact)
    }
    pub async fn receive_ciphertext(
        &mut self,
        prepared: Prepared,
        signature: Vec<u8>,
    ) -> Result<PendingCiphertext, Error> {
        let cfrm::Request::Ciphertext(request) = prepared.request() else {
            return Err(Error::Rejected);
        };
        let owner = request.owner.clone();
        let revision = request.revision.clone();
        let requester = self.link.publication().ok_or(Error::Rejected)?;
        let reply = self
            .link
            .execute(prepared, signature)
            .await
            .map_err(|_| Error::Rejected)?;
        let cfrm::Output::Ciphertext(output) = reply.response else {
            return Err(Error::Rejected);
        };
        if self.link.publication().as_ref() != Some(&requester) {
            return Err(Error::Rejected);
        }
        Ok(PendingCiphertext {
            bytes: output.ciphertext,
            requester,
            owner,
            revision,
        })
    }
    pub fn finish_ciphertext(
        &self,
        pending: PendingCiphertext,
        inputs: (Input<'_>, Input<'_>),
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<u8>, Error> {
        self.current_verification(verification)?;
        self.own_publication(inputs.0)?;
        if inputs.0.bytes != pending.requester {
            return Err(Error::Rejected);
        }
        let pair = csrh::recheck(inputs.0, inputs.1, verification, contact)
            .map_err(|_| Error::Rejected)?;
        if !pair.decision().is_match()
            || pending.owner != inputs.1.member.as_bytes()
            || pending.revision != pair.owner().transcript().revision.to_be_bytes()
        {
            return Err(Error::Rejected);
        }
        let expected = cpfl::Publication::from_bytes(inputs.1.bytes)
            .map_err(|_| Error::Rejected)?
            .envelope;
        if pending.bytes != expected {
            return Err(Error::Rejected);
        }
        Ok(pending.bytes)
    }
    /// Recheck the held original bytes against actual current local authority
    /// before every display; changed own blocks/credentials clear the view.
    pub fn read_search(
        &mut self,
        requester: Input<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<csrh::CheckedPair>, Error> {
        if self.current_verification(verification).is_err()
            || self.own_publication(requester).is_err()
        {
            self.clear_view();
            return Err(Error::Rejected);
        }
        self.search
            .as_mut()
            .ok_or(Error::Unavailable)?
            .read(requester, verification, contact)
            .map_err(|_| Error::Rejected)
    }
    /// Revalidate the same current owner inputs before projecting public display
    /// data. Shells consume this owner DTO instead of serializing CheckedPair.
    pub fn read_discovery(
        &mut self,
        requester: Input<'_>,
        verification: &Verification<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Vec<Discovery>, Error> {
        Ok(self
            .read_search(requester, verification, contact)?
            .iter()
            .filter_map(|pair| pair.discovery())
            .collect())
    }
    /// Contacts invokes this after its actual local block/removal commit.
    pub fn remove(&mut self, member: &str) {
        // A local committed removal invalidates the server's previous window.
        // No later delta may reinsert an entry against that superseded baseline.
        self.watch = None;
        if let Some(search) = &mut self.search {
            search.remove(member);
        }
    }
    fn own_publication(&self, requester: Input<'_>) -> Result<(), Error> {
        if self.link.publication().as_deref() != Some(requester.bytes) {
            return Err(Error::Rejected);
        }
        Ok(())
    }
    fn clear_view(&mut self) {
        self.watch = None;
        if let Some(search) = &mut self.search {
            search.clear();
        }
    }
    /// Clear live Link state. Pending durable owners still require reconciliation.
    pub fn disconnect(&mut self) {
        self.link.disconnect();
        self.clear_view();
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
    /// Local give-first inspection from an original Auth-mode Envelope capsule.
    /// Exchange rechecks the exact signed pair and retains no received key.
    /// This does not authorize outgoing keys, notices, transport or replay adoption.
    pub fn inspect_transfer(
        &self,
        offer: &cxch::Offer,
        inputs: (csrh::Input<'_>, csrh::Input<'_>),
        verification: &csrh::Verification<'_>,
        transfer: &cnvl::KeyTransfer,
        custody: &cnvl::Custodian<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<cxch::Inspection, Error> {
        self.scope(verification)?;
        cxch::inspect_transfer(offer, inputs, verification, transfer, custody, contact)
            .map_err(|_| Error::Rejected)
    }
    fn current_verification(&self, verification: &Verification<'_>) -> Result<(), Error> {
        self.scope(verification)?;
        if self.link.now_ms().map_err(|_| Error::Unavailable)? / 1000
            != verification.policy.policy.now
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }
    fn scope(&self, verification: &csrh::Verification<'_>) -> Result<(), Error> {
        if verification.policy.policy.community != self.community {
            return Err(Error::Scope);
        }
        Ok(())
    }
}

impl<T: clnk::Transport, R: clnk::Transport> Board<T, clnk::AnonymousRooms<R>> {
    pub fn prepare_room_epoch(&self, nonce: clnk::cmbl::Id) -> Result<Prepared, clnk::ErrorCode> {
        self.link.prepare_room_epoch(nonce)
    }
    pub async fn receive_room_epoch(
        &mut self,
        prepared: Prepared,
        signature: Vec<u8>,
    ) -> Result<(), clnk::ErrorCode> {
        self.link.receive_room_epoch(prepared, signature).await
    }
    pub fn prepare_room_pass(
        &mut self,
        room: clnk::cmbl::Id,
        operation: clnk::cmbl::Id,
        nonce: clnk::cmbl::Id,
    ) -> Result<Prepared, clnk::ErrorCode> {
        self.link.prepare_room_pass(room, operation, nonce)
    }
    pub async fn receive_room_pass(
        &mut self,
        prepared: Prepared,
        signature: Vec<u8>,
    ) -> Result<clnk::cmbl::Id, clnk::ErrorCode> {
        self.link.receive_room_pass(prepared, signature).await
    }
    pub fn room_connection(&self, room: clnk::cmbl::Id) -> Result<clnk::cmbl::Id, clnk::ErrorCode> {
        self.link.room_connection(room)
    }
    /// Assembly transport only. MLS membership/counter and key-history handover
    /// remain with Attend/Threads and are not inferred from ordering success.
    pub async fn execute_room(
        &self,
        command: clnk::cmbl::Request,
    ) -> Result<clnk::cmbl::Outcome, clnk::ErrorCode> {
        self.link.execute_room(command).await
    }
    pub fn close_rooms(&mut self) {
        self.link.close_rooms();
    }
}
