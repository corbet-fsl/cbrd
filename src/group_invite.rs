//! Group consent over contact conversations. A group command that needs other
//! members is first proposed: the actor signs only its own consent and sends
//! the unsigned request to each other member's conversation. Every member
//! answers for themselves on their own device (nothing is automatic); the
//! actor adds the answers and only a complete set reaches `cgrp::prepare`,
//! which still re-checks contacts, standing, devices and the policy. Groups
//! stay immutable: a changed membership is always a fork the members consent
//! to; nobody can add or remove another member.
use crate::groups::{
    CONSENT_SECONDS, GroupOwner, Port, Result, command_members, required_consents,
};
use cgrp::{Command, CommittedEffect, Consent, Error, GroupView, Id, PolicySource, Request};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Wire version of [`Message`]; anything else is refused.
pub const INVITE_VERSION: u8 = 1;
/// Longest accepted clock lead of a request over the receiver's clock.
const SKEW_SECONDS: u64 = 300;

/// What travels as the text of a conversation message between two members.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    /// The exact request (without consents) the invitee may consent to.
    Invite { version: u8, request: Request },
    /// One member's signed consent for exactly one request.
    Consent { version: u8, consent: Consent },
    /// The member refused; nothing is signed.
    Decline {
        version: u8,
        operation: Id,
        member: String,
    },
}

impl Message {
    pub fn to_text(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| Error::Invalid)
    }
    pub fn from_text(text: &str) -> Result<Self> {
        let message: Self = serde_json::from_str(text).map_err(|_| Error::Invalid)?;
        let version = match &message {
            Self::Invite { version, .. }
            | Self::Consent { version, .. }
            | Self::Decline { version, .. } => *version,
        };
        if version != INVITE_VERSION {
            return Err(Error::Invalid);
        }
        Ok(message)
    }
}

/// The actor's side: a request waiting for the other members' consents.
#[derive(Clone, Serialize, Deserialize)]
pub struct Proposal {
    request: Request,
    epoch: u64,
    community: String,
    awaiting: BTreeSet<String>,
    declined: bool,
}

impl Proposal {
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn operation(&self) -> Id {
        self.request.operation
    }
    /// Members whose consent is still missing.
    pub fn awaiting(&self) -> &BTreeSet<String> {
        &self.awaiting
    }
    pub fn declined(&self) -> bool {
        self.declined
    }
    /// After this second no answer to the proposal can be admitted.
    pub fn expires_at(&self) -> u64 {
        self.request.effective_at.saturating_add(CONSENT_SECONDS)
    }
    pub fn complete(&self) -> bool {
        self.awaiting.is_empty() && !self.declined
    }
    /// The message for one awaited member; carries no consent of anyone.
    pub fn invitation(&self) -> Message {
        let mut request = self.request.clone();
        request.consents.clear();
        Message::Invite {
            version: INVITE_VERSION,
            request,
        }
    }

    /// Admit one answer. A consent counts only for an awaited member, this
    /// operation, this exact command digest and policy epoch, and while valid.
    /// Its signature and device authority are verified by Groups at commit.
    pub fn admit(&mut self, from: &str, message: Message, now: u64) -> Result<()> {
        match message {
            Message::Consent { consent, .. } => {
                if consent.member != from
                    || !self.awaiting.contains(&consent.member)
                    || consent.community != self.community
                    || consent.operation != self.request.operation
                    || consent.policy_epoch != self.epoch
                    || consent.command_digest != self.request.command_digest()?
                    || consent.valid_until < now
                    || consent.signature.is_empty()
                {
                    return Err(Error::Authority);
                }
                self.awaiting.remove(&consent.member);
                self.request.consents.push(consent);
                Ok(())
            }
            Message::Decline {
                operation, member, ..
            } => {
                if member != from
                    || operation != self.request.operation
                    || !self.awaiting.contains(&member)
                {
                    return Err(Error::Authority);
                }
                self.declined = true;
                Ok(())
            }
            Message::Invite { .. } => Err(Error::Invalid),
        }
    }
}

/// Build one request and sign the local member's own consent only. Other
/// members' consents are never requested from the owner.
pub async fn propose<O: GroupOwner + ?Sized>(
    owner: &mut O,
    policy: &(impl PolicySource + ?Sized),
    command: Command,
    visible: bool,
) -> Result<Proposal> {
    let actor = owner.member()?;
    let now = owner.now()?;
    let snapshot = owner.snapshot().await?;
    let current = policy.current(snapshot.community(), now)?;
    let mut request = Request {
        operation: owner.operation()?,
        parents: snapshot.parent_references(&command)?,
        effective_at: now,
        actor: actor.clone(),
        command,
        consents: vec![],
    };
    let digest = request.command_digest()?;
    let mut awaiting = required_consents(&request.command, &actor);
    if awaiting.remove(&actor) {
        let consent = sign(
            owner,
            snapshot.community(),
            &actor,
            &request,
            current.epoch,
            digest,
            visible,
            now,
        )
        .await?;
        request.consents.push(consent);
    }
    Ok(Proposal {
        request,
        epoch: current.epoch,
        community: snapshot.community().to_owned(),
        awaiting,
        declined: false,
    })
}

/// Prepare and publish a complete proposal. A proposal with a missing or
/// declined consent is refused before Groups is asked.
pub async fn commit<O: GroupOwner + ?Sized>(
    owner: &mut O,
    policy: &(impl PolicySource + ?Sized),
    proposal: &Proposal,
    max_groups: usize,
) -> Result<(Vec<GroupView>, Vec<CommittedEffect>)> {
    if !proposal.complete() {
        return Err(Error::Authority);
    }
    let now = owner.now()?;
    let snapshot = owner.snapshot().await?;
    let current = policy.current(snapshot.community(), now)?;
    owner
        .refresh(
            &command_members(&proposal.request.command),
            &required_consents(&proposal.request.command, &proposal.request.actor),
        )
        .await?;
    let candidate = cgrp::prepare(
        &snapshot,
        &proposal.request,
        &Port(policy),
        &Port(owner.authority()),
        now,
        max_groups,
    )?;
    let (committed, effects) = owner.publish(candidate, now).await?;
    Ok((committed.views(&current, now)?, effects))
}

/// The invitee's side: a verified request waiting for the member's own answer.
#[derive(Clone, Serialize, Deserialize)]
pub struct Invitation {
    request: Request,
    community: String,
    epoch: u64,
    member: String,
}

impl Invitation {
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn operation(&self) -> Id {
        self.request.operation
    }
    pub fn actor(&self) -> &str {
        &self.request.actor
    }
    /// After this second the member's consent would no longer be admitted.
    pub fn expires_at(&self) -> u64 {
        self.request.effective_at.saturating_add(CONSENT_SECONDS)
    }

    /// Check an invitation that arrived in the conversation with `from`. It is
    /// shown to the member, never answered automatically. Refused unless the
    /// sender is the actor and an established contact, the local member is a
    /// consenting party but not the actor, the request is fresh and the
    /// community policy is current.
    pub async fn receive<O: GroupOwner + ?Sized>(
        owner: &mut O,
        policy: &(impl PolicySource + ?Sized),
        from: &str,
        message: Message,
    ) -> Result<Self> {
        let Message::Invite { request, .. } = message else {
            return Err(Error::Invalid);
        };
        let member = owner.member()?;
        let now = owner.now()?;
        let snapshot = owner.snapshot().await?;
        let current = policy.current(snapshot.community(), now)?;
        if request.actor != from
            || member == from
            || !required_consents(&request.command, &request.actor).contains(&member)
            || request.effective_at > now.saturating_add(SKEW_SECONDS)
            || request.effective_at.saturating_add(CONSENT_SECONDS) < now
        {
            return Err(Error::Authority);
        }
        owner
            .refresh(&BTreeSet::from([from.to_owned()]), &BTreeSet::new())
            .await?;
        owner
            .authority()
            .contact(snapshot.community(), &member, from, now)?;
        Ok(Self {
            request,
            community: snapshot.community().to_owned(),
            epoch: current.epoch,
            member,
        })
    }

    /// The member's decision. Accepting signs this member's consent over the
    /// exact command digest; `visible` is the semipublic profile statement.
    pub async fn answer<O: GroupOwner + ?Sized>(
        &self,
        owner: &mut O,
        accept: bool,
        visible: bool,
    ) -> Result<Message> {
        if owner.member()? != self.member {
            return Err(Error::Authority);
        }
        if !accept {
            return Ok(Message::Decline {
                version: INVITE_VERSION,
                operation: self.request.operation,
                member: self.member.clone(),
            });
        }
        let now = owner.now()?;
        let digest = self.request.command_digest()?;
        let consent = sign(
            owner,
            &self.community,
            &self.member,
            &self.request,
            self.epoch,
            digest,
            visible,
            now,
        )
        .await?;
        Ok(Message::Consent {
            version: INVITE_VERSION,
            consent,
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn sign<O: GroupOwner + ?Sized>(
    owner: &mut O,
    community: &str,
    member: &str,
    request: &Request,
    epoch: u64,
    digest: Id,
    visible: bool,
    now: u64,
) -> Result<Consent> {
    let mut consent = Consent {
        community: community.to_owned(),
        member: member.to_owned(),
        operation: request.operation,
        policy_epoch: epoch,
        command_digest: digest,
        profile_visibility: visible,
        valid_until: now.saturating_add(CONSENT_SECONDS),
        signature: vec![],
        authority: vec![],
    };
    let signed = owner
        .sign_consent(member, &consent.signing_bytes()?, consent.valid_until)
        .await?;
    consent.signature = signed.signature;
    consent.authority = signed.authority;
    Ok(consent)
}

impl Proposal {
    /// Durable form for the owner's encrypted records.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| Error::Invalid)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
    }
}

impl Invitation {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| Error::Invalid)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
    }
}
