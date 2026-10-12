//! Group write side. The Board builds the exact signed request, lets Groups
//! decide, and hands the prepared candidate to the owner's durable transaction.
//! Membership is decided only by `cgrp::prepare`; nothing here grants authority.
use cgrp::{
    Authority, Candidate, Command, CommittedEffect, Consent, Id, PolicySource, Request, Snapshot,
};
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
    /// Wall-clock seconds.
    fn now(&mut self) -> Result<u64>;
    /// A fresh operation identifier, never reused.
    fn operation(&mut self) -> Result<Id>;
    fn snapshot(&mut self) -> PortFuture<'_, Snapshot>;
    fn sign_consent<'a>(
        &'a mut self,
        member: &'a str,
        statement: &'a [u8],
        expires: u64,
    ) -> PortFuture<'a, Signed>;
    /// Persist the checkpoint and publish the effects atomically, repeating
    /// current authority checks; returns the committed state.
    fn publish(
        &mut self,
        candidate: Candidate,
        now: u64,
    ) -> PortFuture<'_, (Snapshot, Vec<CommittedEffect>)>;
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

/// Build, sign, prepare and publish one group command. `visible` is the
/// semipublic consent: every signer states that members of the group may see
/// their private profile. Rooms (opening and public) refuse a command without it.
pub async fn execute<O: GroupOwner>(
    owner: &mut O,
    policy: &impl PolicySource,
    authority: &impl Authority,
    command: Command,
    actor: &str,
    visible: bool,
    max_groups: usize,
) -> Result<(Snapshot, Vec<CommittedEffect>)> {
    let now = owner.now()?;
    let snapshot = owner.snapshot().await?;
    let epoch = policy.current(snapshot.community(), now)?.epoch;
    let mut request = Request {
        operation: owner.operation()?,
        parents: snapshot.parent_references(&command)?,
        effective_at: now,
        actor: actor.to_owned(),
        command,
        consents: vec![],
    };
    let digest = request.command_digest()?;
    for member in required_consents(&request.command, actor) {
        let mut consent = Consent {
            community: snapshot.community().to_owned(),
            member,
            operation: request.operation,
            policy_epoch: epoch,
            command_digest: digest,
            profile_visibility: visible,
            valid_until: now.saturating_add(CONSENT_SECONDS),
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
    let candidate = cgrp::prepare(&snapshot, &request, policy, authority, now, max_groups)?;
    owner.publish(candidate, now).await
}
