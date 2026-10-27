//! Group write side. The Board builds the exact signed request, lets Groups
//! decide, and hands the prepared candidate to the owner's durable transaction.
//! Membership is decided only by `cgrp::prepare`; nothing here grants authority.
use cgrp::{
    Authority, Candidate, Command, CommittedEffect, Consent, GroupView, Id, Policy, PolicySource,
    Request, Snapshot,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

pub type Result<T> = std::result::Result<T, cgrp::Error>;
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// How long a signed consent stays valid; it is bound to one exact command.
pub const CONSENT_SECONDS: u64 = 3_600;

/// A device signature over exact consent bytes plus the evidence of the
/// signing device's authority (verified later by `Devices`).
pub struct Signed {
    pub signature: Vec<u8>,
    pub authority: Vec<u8>,
}

/// The parent's owner of everything the Board may not hold itself: the
/// encrypted checkpoint, the device signer and the atomic publication
/// transaction (Threads). A peer's consent is available only when the peer
/// answered an invitation; otherwise `sign_consent` refuses.
pub trait GroupOwner {
    /// The local member string as it appears in group rosters.
    fn member(&mut self) -> Result<String>;
    /// Current Guard/device/contact authority for this device.
    fn authority(&self) -> &dyn Authority;
    /// Wall-clock seconds.
    fn now(&mut self) -> Result<u64>;
    /// A fresh operation identifier, never reused.
    fn operation(&mut self) -> Result<Id>;
    fn snapshot(&mut self) -> PortFuture<'_, Snapshot>;
    /// Called before Groups asks the synchronous `authority`: load the current
    /// contact relations of `contacts` and the current device sets of `devices`
    /// (fresh reads, never stale values). Whatever cannot be loaded must make
    /// `authority` refuse. Owners whose authority needs no loading keep the default.
    fn refresh<'a>(
        &'a mut self,
        _contacts: &'a BTreeSet<String>,
        _devices: &'a BTreeSet<String>,
    ) -> PortFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn sign_consent<'a>(
        &'a mut self,
        member: &'a str,
        statement: &'a [u8],
        expires: u64,
    ) -> PortFuture<'a, Signed>;
    /// The durable bytes of this member's pending proposals and invitations, if
    /// the owner keeps any. Owners without durable storage keep the default.
    fn desk_load(&mut self) -> PortFuture<'_, Option<Vec<u8>>> {
        Box::pin(async { Ok(None) })
    }
    /// Replace the durable desk bytes.
    fn desk_save<'a>(&'a mut self, _bytes: &'a [u8]) -> PortFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    /// Persist the checkpoint and publish the effects atomically, repeating
    /// current authority checks; returns the committed state.
    fn publish(
        &mut self,
        candidate: Candidate,
        now: u64,
    ) -> PortFuture<'_, (Snapshot, Vec<CommittedEffect>)>;
    /// This member's OWN lineage-read handle, attached to every consent it
    /// signs (covered by the signature). Owners that cannot read a lineage
    /// keep the default (no handle: nobody can then verify the consent).
    fn own_handle(&mut self) -> PortFuture<'_, Vec<u8>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// The handles the signers attached to their own consents. They take
    /// precedence over the own journal: they are the signer's current locator.
    fn provide_handles(&mut self, _handles: std::collections::BTreeMap<String, Vec<u8>>) {}
    /// A fresh MLS key package this member makes for the group `group` that
    /// operation `operation` creates. Its private half stays in the owner's
    /// store; the consent signature binds the public bytes. Owners without a
    /// Threads store keep the default (no package).
    fn key_package<'a>(&'a mut self, _group: Id, _operation: Id) -> PortFuture<'a, Vec<u8>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// The creating member's publication: Groups and the MLS group (built from
    /// the other members' key packages carried by `request`'s consents) become
    /// visible in one durable write. Returns the Welcome the other members need
    /// when an MLS group was created. The default is `publish` without MLS.
    fn publish_request<'a>(
        &'a mut self,
        candidate: Candidate,
        _request: &'a Request,
        _policy: &'a dyn PolicySource,
        now: u64,
    ) -> PortFuture<'a, Published> {
        Box::pin(async move {
            let (snapshot, effects) = self.publish(candidate, now).await?;
            Ok(Published {
                snapshot,
                effects,
                welcome: None,
            })
        })
    }
    /// A consenting member's publication from a received Welcome: Groups and
    /// the joined MLS group become visible in one durable write.
    fn publish_welcome<'a>(
        &'a mut self,
        _candidate: Candidate,
        _group: Id,
        _welcome: &'a [u8],
        _policy: &'a dyn PolicySource,
        _now: u64,
    ) -> PortFuture<'a, (Snapshot, Vec<CommittedEffect>)> {
        Box::pin(async { Err(cgrp::Error::Unavailable) })
    }
}

/// What a creating member's publication produced.
pub struct Published {
    pub snapshot: Snapshot,
    pub effects: Vec<CommittedEffect>,
    /// The MLS Welcome for the other members, if a group was created.
    pub welcome: Option<Vec<u8>>,
}

/// The group a command creates, if it creates one (and so needs MLS).
pub fn created_group(command: &Command) -> Option<Id> {
    match command {
        Command::Create { id, .. } | Command::Fork { id, .. } => Some(*id),
        _ => None,
    }
}

/// Everyone whose signed consent the command needs.
pub fn required_consents(command: &Command, actor: &str) -> BTreeSet<String> {
    match command {
        Command::Create { members, .. } | Command::Fork { members, .. } => members.clone(),
        Command::Join {
            member, vouches, ..
        } => vouches.iter().cloned().chain([member.clone()]).collect(),
        Command::Leave { .. } | Command::Describe { .. } => BTreeSet::from([actor.to_owned()]),
        Command::Tick => BTreeSet::new(),
    }
}

/// Every member a command names, whom the actor must hold as contacts.
pub fn command_members(command: &Command) -> BTreeSet<String> {
    match command {
        Command::Create { members, .. } | Command::Fork { members, .. } => members.clone(),
        Command::Join {
            member, vouches, ..
        } => vouches.iter().cloned().chain([member.clone()]).collect(),
        _ => BTreeSet::new(),
    }
}

/// A policy already verified from the signed Rulebook for one moment: Groups
/// re-validates it at the given time, so it grants nothing beyond its expiry.
pub struct PolicyAt {
    community: String,
    policy: Policy,
}
impl PolicyAt {
    pub fn new(community: &str, policy: Policy) -> Self {
        Self {
            community: community.to_owned(),
            policy,
        }
    }
}
impl PolicySource for PolicyAt {
    fn current(&self, community: &str, now: u64) -> Result<Policy> {
        if community != self.community {
            return Err(cgrp::Error::Authority);
        }
        self.policy.validate(now)?;
        Ok(self.policy.clone())
    }
}

/// Sized view of an unsized port, so the object-safe owner can feed Groups.
pub(crate) struct Port<'a, T: ?Sized>(pub(crate) &'a T);
impl<T: PolicySource + ?Sized> PolicySource for Port<'_, T> {
    fn current(&self, community: &str, now: u64) -> Result<Policy> {
        self.0.current(community, now)
    }
}
impl<T: Authority + ?Sized> Authority for Port<'_, T> {
    fn consent(&self, consent: &Consent, now: u64) -> Result<()> {
        self.0.consent(consent, now)
    }
    fn contact(&self, community: &str, member: &str, contact: &str, now: u64) -> Result<()> {
        self.0.contact(community, member, contact, now)
    }
    fn parent(
        &self,
        state: &cgrp::GroupState,
        request: &Request,
        policy: &Policy,
        now: u64,
    ) -> Result<()> {
        self.0.parent(state, request, policy, now)
    }
}

/// Build, sign and prepare one group command as the local member, without
/// publishing it: the caller decides how the prepared Candidate becomes durable
/// (a plain publication, or the ordered external commit of a room join, which
/// also needs the signed `Request` as its companion).
pub async fn prepare_command<O: GroupOwner + ?Sized>(
    owner: &mut O,
    policy: &(impl PolicySource + ?Sized),
    command: Command,
    max_groups: usize,
) -> Result<(Candidate, Policy, u64, Request)> {
    prepare_inner(owner, policy, command, max_groups, None).await
}

/// The Join of a newcomer who holds no checkpoint of the group: the parent is
/// the delivered room state, already authenticated against the MLS evidence by
/// `cthr::Threads::verify_room_state` (which the caller MUST have passed before
/// this call). The request names that state's commitment, and the Authority
/// wrapper accepts exactly that state for exactly this Join, nothing else.
/// Nothing is sent or stored here.
pub async fn prepare_join_from_state<O: GroupOwner + ?Sized>(
    owner: &mut O,
    policy: &(impl PolicySource + ?Sized),
    group: Id,
    vouches: BTreeSet<String>,
    state: &cgrp::GroupState,
    max_groups: usize,
) -> Result<(Candidate, Policy, u64, Request)> {
    if state.id() != &group {
        return Err(cgrp::Error::Authority);
    }
    let command = Intent::Join { group, vouches }.command(&owner.member()?);
    prepare_inner(owner, policy, command, max_groups, Some(state)).await
}

/// Accepts only the one verified state as the parent of the one Join. Groups
/// asks again at publication, so the same wrapper rides with the join.
pub struct JoinParent<'a, A: ?Sized> {
    inner: &'a A,
    state: &'a cgrp::GroupState,
}
impl<'a, A: ?Sized> JoinParent<'a, A> {
    pub fn new(inner: &'a A, state: &'a cgrp::GroupState) -> Self {
        Self { inner, state }
    }
}
impl<A: Authority + ?Sized> Authority for JoinParent<'_, A> {
    fn consent(&self, consent: &Consent, now: u64) -> Result<()> {
        self.inner.consent(consent, now)
    }
    fn contact(&self, community: &str, member: &str, contact: &str, now: u64) -> Result<()> {
        self.inner.contact(community, member, contact, now)
    }
    fn parent(
        &self,
        state: &cgrp::GroupState,
        request: &Request,
        _: &Policy,
        _: u64,
    ) -> Result<()> {
        match &request.command {
            Command::Join { group, .. }
                if state == self.state && state.id() == group && request.parents.len() == 1 =>
            {
                Ok(())
            }
            _ => Err(cgrp::Error::Authority),
        }
    }
}

async fn prepare_inner<O: GroupOwner + ?Sized>(
    owner: &mut O,
    policy: &(impl PolicySource + ?Sized),
    command: Command,
    max_groups: usize,
    delivered: Option<&cgrp::GroupState>,
) -> Result<(Candidate, Policy, u64, Request)> {
    let actor = owner.member()?;
    let now = owner.now()?;
    let snapshot = owner.snapshot().await?;
    let current = policy.current(snapshot.community(), now)?;
    let mut request = Request {
        operation: owner.operation()?,
        parents: match delivered {
            Some(state) => vec![cgrp::ParentRef {
                id: *state.id(),
                commitment: state.commitment()?,
            }],
            None => snapshot.parent_references(&command)?,
        },
        effective_at: now,
        actor: actor.clone(),
        command,
        consents: vec![],
    };
    let digest = request.command_digest()?;
    owner
        .refresh(
            &command_members(&request.command),
            &required_consents(&request.command, &actor),
        )
        .await?;
    let lineage_handle = owner.own_handle().await?;
    for member in required_consents(&request.command, &actor) {
        let mut consent = Consent {
            community: snapshot.community().to_owned(),
            member,
            operation: request.operation,
            policy_epoch: current.epoch,
            command_digest: digest,
            profile_visibility: request.command.exposes_profile(),
            valid_until: now.saturating_add(CONSENT_SECONDS),
            key_package: vec![],
            lineage_handle: lineage_handle.clone(),
            signature: vec![],
            authority: vec![],
        };
        let signed = owner
            .sign_consent(
                &consent.member,
                &consent.signing_bytes()?,
                consent.valid_until,
            )
            .await?;
        consent.signature = signed.signature;
        consent.authority = signed.authority;
        request.consents.push(consent);
    }
    let candidate = match delivered {
        Some(state) => cgrp::prepare_with_parents(
            &snapshot,
            &request,
            std::slice::from_ref(state),
            &Port(policy),
            &JoinParent {
                inner: &Port(owner.authority()),
                state,
            },
            now,
            max_groups,
        )?,
        None => cgrp::prepare(
            &snapshot,
            &request,
            &Port(policy),
            &Port(owner.authority()),
            now,
            max_groups,
        )?,
    };
    Ok((candidate, current, now, request))
}

/// Build, sign, prepare and publish one group command as the local member.
/// Joining a public room is the consent to visible profiles (decided
/// 2026-10-13): every signer's statement is derived from the command itself
/// (`Command::exposes_profile`); there is no per-call switch.
pub async fn execute<O: GroupOwner + ?Sized>(
    owner: &mut O,
    policy: &(impl PolicySource + ?Sized),
    command: Command,
    max_groups: usize,
) -> Result<(Vec<GroupView>, Vec<CommittedEffect>)> {
    let (candidate, current, now, _) = prepare_command(owner, policy, command, max_groups).await?;
    let (committed, effects) = owner.publish(candidate, now).await?;
    Ok((committed.views(&current, now)?, effects))
}

/// What the member asks for. The local member is never named by the caller;
/// the owner supplies it, so nobody can act or consent for someone else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "intent", rename_all = "snake_case", deny_unknown_fields)]
pub enum Intent {
    Create {
        id: Id,
        members: BTreeSet<String>,
    },
    Fork {
        id: Id,
        parents: Vec<Id>,
        members: BTreeSet<String>,
        kind: cgrp::ForkKind,
    },
    Join {
        group: Id,
        vouches: BTreeSet<String>,
    },
    Leave {
        group: Id,
    },
    Describe {
        group: Id,
        name: String,
        description: String,
    },
}

impl Intent {
    pub fn command(self, member: &str) -> Command {
        match self {
            Self::Create { id, members } => Command::Create { id, members },
            Self::Fork {
                id,
                parents,
                members,
                kind,
            } => Command::Fork {
                id,
                parents,
                members,
                kind,
            },
            Self::Join { group, vouches } => Command::Join {
                group,
                member: member.to_owned(),
                vouches,
            },
            Self::Leave { group } => Command::Leave { group },
            Self::Describe {
                group,
                name,
                description,
            } => Command::Describe {
                group,
                name,
                description,
            },
        }
    }
}

/// `execute` for an intent of the local member.
pub async fn execute_intent<O: GroupOwner + ?Sized>(
    owner: &mut O,
    policy: &(impl PolicySource + ?Sized),
    intent: Intent,
    max_groups: usize,
) -> Result<(Vec<GroupView>, Vec<CommittedEffect>)> {
    let command = intent.command(&owner.member()?);
    execute(owner, policy, command, max_groups).await
}

/// `prepare_command` for an intent of the local member.
pub async fn prepare_intent<O: GroupOwner + ?Sized>(
    owner: &mut O,
    policy: &(impl PolicySource + ?Sized),
    intent: Intent,
    max_groups: usize,
) -> Result<(Candidate, Policy, u64, Request)> {
    let command = intent.command(&owner.member()?);
    prepare_command(owner, policy, command, max_groups).await
}
