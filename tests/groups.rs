//! Group write side through the Board: real Groups decisions, real ed25519
//! consents, fake device directory, contacts and checkpoint store.
use cbrd::cgrp::{
    self, Band, Candidate, Command, Commit, CommitFuture, CommittedEffect, DAY, Effect, Error, Id,
    Notification, Persistence, Policy, SeatFormats, Snapshot,
};
use cbrd::{BoardAuthority, Contacts, Devices, GroupOwner, PolicyAt, PortFuture, Signed};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::BTreeSet;

const COMMUNITY: &str = "alpha";

fn names(start: usize, end: usize) -> BTreeSet<String> {
    (start..end).map(|i| format!("m{i}")).collect()
}

fn key(member: &str) -> SigningKey {
    SigningKey::from_bytes(ckmg::hash(member.as_bytes()).value())
}

fn policy() -> Policy {
    let edges = [3, 6, 9, 13, 20, 30, 43, 60, 80];
    let posts = [120, 90, 60, 40, 30, 24, 18, 12, 8];
    let bursts = [20, 15, 12, 10, 8, 6, 5, 4, 3];
    let notifications = [
        Notification::EveryMessage,
        Notification::QuietHours,
        Notification::SilentReactions,
        Notification::MentionsReplies,
        Notification::MentionsRepliesDigest,
        Notification::MentionsDigest,
        Notification::MentionsDaily,
        Notification::MentionsDaily,
        Notification::ContactsWeekly,
    ];
    Policy {
        epoch: 1,
        valid_until: 1_000 * DAY,
        cap: 100,
        circle_max: 12,
        ingroup_max: 42,
        shrink_public: 36,
        shrink_ingroup: 10,
        open_seconds: 21 * DAY,
        fork_cooldown: 14 * DAY,
        retarget_cooldown: 28 * DAY,
        listing_wait: 72 * 3_600,
        split_public_min: 43,
        bands: std::array::from_fn(|i| Band {
            lower: edges[i],
            enter_up: edges[i],
            leave_down: edges[i] - 2,
            notification: notifications[i],
            posts_per_hour: posts[i],
            burst: bursts[i],
            vouches: if i == 5 {
                2
            } else if (3..5).contains(&i) {
                1
            } else {
                0
            },
            history_seconds: [0, 0, 0, 14 * DAY, 7 * DAY, 3 * DAY, DAY, DAY / 2, DAY / 4][i],
            history_messages: [0, 0, 0, 200, 200, 200, 100, 50, 50][i],
            joins_per_hour: if i >= 7 { Some(6) } else { None },
        }),
        seats: SeatFormats {
            enabled: false,
            refill_per_day: 1.0,
            capacity: 10.0,
            initial: 5.0,
            minimum: 0.25,
            small: 1.5,
            large: 3.0,
            low: 7,
            high: 60,
            tau: 1.0,
            epoch_days: 7,
            quantum: 0.5,
            warning_days: 2,
        },
        suggest_at: 66,
        pressure_at: 85,
        modularity: 0.3,
        overlap: 0.4,
        suggestion_cooldown: 7 * DAY,
        decline_cooldown: 14 * DAY,
        reciprocity_enabled: true,
        welcome_quarters: 1,
        introduction_quarters: 4,
        week_cap_quarters: 6,
    }
}

struct Directory;
impl Devices for Directory {
    fn verify(
        &self,
        _: &str,
        member: &str,
        message: &[u8],
        signature: &[u8],
        authority: &[u8],
        _: u64,
    ) -> cgrp::Result<()> {
        let public: [u8; 32] = authority.try_into().map_err(|_| Error::Authority)?;
        if public != key(member).verifying_key().to_bytes() {
            return Err(Error::Authority);
        }
        let signature = Signature::from_slice(signature).map_err(|_| Error::Authority)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| Error::Authority)?
            .verify(message, &signature)
            .map_err(|_| Error::Authority)
    }
}
struct Everyone;
impl Contacts for Everyone {
    fn established(&self, _: &str, _: &str, _: &str, _: u64) -> cgrp::Result<()> {
        Ok(())
    }
}
struct Checkpoint(u64);
impl Persistence for Checkpoint {
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        c: &'a Snapshot,
        _: &'a [Effect],
    ) -> CommitFuture<'a> {
        Box::pin(async move {
            if expected != self.0 {
                return Ok(Commit::Conflict);
            }
            self.0 = c.revision();
            Ok(Commit::Applied)
        })
    }
}

struct Owner {
    me: String,
    authority: BoardAuthority<Directory, Everyone>,
    snapshot: Snapshot,
    store: Checkpoint,
    clock: u64,
    operations: u8,
    /// Members who answered the invitation; others refuse.
    answered: BTreeSet<String>,
    fail_clock: bool,
    /// Pretend to own an MLS store: key packages, Welcome and join.
    mls: bool,
    held: std::collections::BTreeMap<String, Vec<u8>>,
    provided: std::collections::BTreeMap<String, Vec<u8>>,
    packages_seen: Vec<Vec<u8>>,
    joined_with: Option<Vec<u8>>,
}
impl Owner {
    fn new(me: &str, answered: BTreeSet<String>) -> Self {
        let snapshot = Snapshot::empty(COMMUNITY.into());
        Self {
            me: me.into(),
            authority: BoardAuthority::new(Directory, Everyone),
            store: Checkpoint(snapshot.revision()),
            snapshot,
            clock: 1_000_000,
            operations: 0,
            answered,
            fail_clock: false,
            mls: false,
            held: Default::default(),
            provided: Default::default(),
            packages_seen: vec![],
            joined_with: None,
        }
    }
}
impl GroupOwner for Owner {
    fn own_handle(&mut self) -> PortFuture<'_, Vec<u8>> {
        let handle = self.held.get(&self.me).cloned().unwrap_or_default();
        Box::pin(async move { Ok(handle) })
    }
    fn provide_handles(&mut self, handles: std::collections::BTreeMap<String, Vec<u8>>) {
        self.provided = handles;
    }
    fn key_package<'a>(&'a mut self, group: Id, operation: Id) -> PortFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if !self.mls {
                return Ok(Vec::new());
            }
            let mut package = self.me.clone().into_bytes();
            package.extend_from_slice(&group);
            package.extend_from_slice(&operation);
            Ok(package)
        })
    }
    fn publish_request<'a>(
        &'a mut self,
        candidate: Candidate,
        request: &'a cgrp::Request,
        _: &'a dyn cgrp::PolicySource,
        now: u64,
    ) -> PortFuture<'a, cbrd::Published> {
        Box::pin(async move {
            if self.mls {
                self.packages_seen = request
                    .consents
                    .iter()
                    .filter(|consent| consent.member != request.actor)
                    .map(|consent| consent.key_package.clone())
                    .collect();
            }
            let (snapshot, effects) = candidate.persist(&mut self.store, now).await?;
            self.snapshot = snapshot.clone();
            Ok(cbrd::Published {
                snapshot,
                effects,
                welcome: self.mls.then(|| b"welcome".to_vec()),
            })
        })
    }
    fn publish_welcome<'a>(
        &'a mut self,
        candidate: Candidate,
        _group: Id,
        welcome: &'a [u8],
        _: &'a dyn cgrp::PolicySource,
        now: u64,
    ) -> PortFuture<'a, (Snapshot, Vec<CommittedEffect>)> {
        Box::pin(async move {
            let (snapshot, effects) = candidate.persist(&mut self.store, now).await?;
            self.snapshot = snapshot.clone();
            self.joined_with = Some(welcome.to_vec());
            Ok((snapshot, effects))
        })
    }
    fn member(&mut self) -> cgrp::Result<String> {
        Ok(self.me.clone())
    }
    fn authority(&self) -> &dyn cgrp::Authority {
        &self.authority
    }
    fn now(&mut self) -> cgrp::Result<u64> {
        if self.fail_clock {
            return Err(Error::Clock);
        }
        self.clock += 100;
        Ok(self.clock)
    }
    fn operation(&mut self) -> cgrp::Result<Id> {
        self.operations += 1;
        Ok([self.operations; 32])
    }
    fn snapshot(&mut self) -> PortFuture<'_, Snapshot> {
        Box::pin(async move { Ok(self.snapshot.clone()) })
    }
    fn sign_consent<'a>(
        &'a mut self,
        member: &'a str,
        statement: &'a [u8],
        _: u64,
    ) -> PortFuture<'a, Signed> {
        Box::pin(async move {
            if !self.answered.contains(member) {
                return Err(Error::Unavailable);
            }
            let key = key(member);
            Ok(Signed {
                signature: key.sign(statement).to_bytes().to_vec(),
                authority: key.verifying_key().to_bytes().to_vec(),
            })
        })
    }
    fn publish(
        &mut self,
        candidate: Candidate,
        now: u64,
    ) -> PortFuture<'_, (Snapshot, Vec<CommittedEffect>)> {
        Box::pin(async move {
            let (snapshot, effects) = candidate.persist(&mut self.store, now).await?;
            self.snapshot = snapshot.clone();
            Ok((snapshot, effects))
        })
    }
}

fn run(owner: &mut Owner, command: Command, visible: bool) -> cgrp::Result<Snapshot> {
    futures_executor::block_on(cbrd::execute_group_command(
        owner,
        &PolicyAt::new(COMMUNITY, policy()),
        command,
        visible,
        128,
    ))?;
    Ok(owner.snapshot.clone())
}

fn as_member(owner: &mut Owner, member: &str) {
    owner.me = member.into();
}

#[test]
fn a_circle_is_created_described_and_left_with_every_member_consenting() {
    let mut owner = Owner::new("m0", names(0, 3));
    let create = Command::Create {
        id: [1; 32],
        members: names(0, 3),
    };
    let snapshot = run(&mut owner, create, false).unwrap();
    assert_eq!(snapshot.members(&[1; 32]).unwrap(), &names(0, 3));

    as_member(&mut owner, "m1");
    let describe = Command::Describe {
        group: [1; 32],
        name: "Hike".into(),
        description: "Walks".into(),
    };
    run(&mut owner, describe, false).unwrap();
    as_member(&mut owner, "m2");
    let snapshot = run(&mut owner, Command::Leave { group: [1; 32] }, false).unwrap();
    assert_eq!(snapshot.members(&[1; 32]).unwrap(), &names(0, 2));
    assert_eq!(owner.store.0, snapshot.revision());
    as_member(&mut owner, "m0");
    run(&mut owner, Command::Tick, false).unwrap();
}

#[test]
fn a_command_without_every_required_answer_changes_nothing() {
    let mut owner = Owner::new("m0", names(0, 2));
    let create = Command::Create {
        id: [1; 32],
        members: names(0, 3),
    };
    assert_eq!(
        run(&mut owner, create, false).err().unwrap(),
        Error::Unavailable
    );
    assert_eq!(owner.snapshot.revision(), 0);
    owner.fail_clock = true;
    assert_eq!(
        run(&mut owner, Command::Tick, false).err().unwrap(),
        Error::Clock
    );
}

#[test]
fn joining_a_room_states_the_profile_visibility_consent() {
    let mut owner = Owner::new("m0", names(0, 45));
    let circle = Command::Create {
        id: [1; 32],
        members: names(0, 12),
    };
    run(&mut owner, circle, false).unwrap();
    let ingroup = Command::Fork {
        id: [2; 32],
        parents: vec![[1; 32]],
        members: names(0, 42),
        kind: cgrp::ForkKind::Add,
    };
    run(&mut owner, ingroup, false).unwrap();
    let open = Command::Fork {
        id: [3; 32],
        parents: vec![[2; 32]],
        members: names(0, 42),
        kind: cgrp::ForkKind::Open,
    };
    // Opening a room needs every member's visibility consent.
    assert_eq!(
        run(&mut owner, open.clone(), false).err().unwrap(),
        Error::Authority
    );
    run(&mut owner, open, true).unwrap();
    as_member(&mut owner, "m44");
    let join = Command::Join {
        group: [3; 32],
        member: "m44".into(),
        vouches: BTreeSet::new(),
    };
    assert_eq!(
        run(&mut owner, join.clone(), false).err().unwrap(),
        Error::Authority
    );
    let snapshot = run(&mut owner, join, true).unwrap();
    assert!(snapshot.members(&[3; 32]).unwrap().contains("m44"));
}

#[test]
fn required_consents_name_exactly_the_people_who_must_sign() {
    let fork = Command::Fork {
        id: [3; 32],
        parents: vec![[1; 32]],
        members: names(0, 4),
        kind: cgrp::ForkKind::Split,
    };
    assert_eq!(cbrd::required_consents(&fork, "m0"), names(0, 4));
    let join = Command::Join {
        group: [1; 32],
        member: "m9".into(),
        vouches: names(1, 3),
    };
    assert_eq!(
        cbrd::required_consents(&join, "m9"),
        BTreeSet::from(["m1".into(), "m2".into(), "m9".into()])
    );
    assert_eq!(
        cbrd::required_consents(&Command::Leave { group: [1; 32] }, "m5"),
        BTreeSet::from(["m5".to_string()])
    );
    assert!(cbrd::required_consents(&Command::Tick, "m5").is_empty());
}

#[test]
fn the_authority_adapter_checks_expiry_and_leaves_parent_imports_refused() {
    use cgrp::Authority;
    let authority = BoardAuthority::new(Directory, Everyone);
    let mut consent = cgrp::Consent {
        community: COMMUNITY.into(),
        member: "m0".into(),
        operation: [1; 32],
        policy_epoch: 1,
        command_digest: [2; 32],
        profile_visibility: false,
        valid_until: 10,
        key_package: vec![],
        lineage_handle: vec![],
        signature: vec![],
        authority: key("m0").verifying_key().to_bytes().to_vec(),
    };
    consent.signature = key("m0")
        .sign(&consent.signing_bytes().unwrap())
        .to_bytes()
        .to_vec();
    assert_eq!(authority.consent(&consent, 5), Ok(()));
    assert_eq!(authority.consent(&consent, 10), Err(Error::Authority));
    consent.member = "m1".into();
    assert_eq!(authority.consent(&consent, 5), Err(Error::Authority));
    assert_eq!(authority.contact(COMMUNITY, "m0", "m1", 5), Ok(()));
    assert_eq!(cbrd::CONSENT_SECONDS, 3_600);
}

#[test]
fn an_intent_always_names_the_local_member() {
    use cbrd::GroupIntent;
    let join = GroupIntent::Join {
        group: [1; 32],
        vouches: BTreeSet::new(),
    };
    assert_eq!(
        join.clone().command("m7"),
        Command::Join {
            group: [1; 32],
            member: "m7".into(),
            vouches: BTreeSet::new()
        }
    );
    let others = [
        GroupIntent::Create {
            id: [2; 32],
            members: names(0, 3),
        },
        GroupIntent::Fork {
            id: [3; 32],
            parents: vec![[2; 32]],
            members: names(0, 3),
            kind: cgrp::ForkKind::Split,
        },
        GroupIntent::Leave { group: [2; 32] },
        GroupIntent::Describe {
            group: [2; 32],
            name: "n".into(),
            description: "d".into(),
        },
    ];
    for intent in others {
        let json = serde_json::to_string(&intent).unwrap();
        assert_eq!(serde_json::from_str::<GroupIntent>(&json).unwrap(), intent);
        assert!(!matches!(intent.command("m7"), Command::Join { .. }));
    }
    assert!(
        serde_json::from_str::<GroupIntent>(r#"{"intent":"leave","group":[],"member":"x"}"#)
            .is_err()
    );
    // Executing an intent acts as the owner's member.
    let mut owner = Owner::new("m0", names(0, 3));
    let create = GroupIntent::Create {
        id: [1; 32],
        members: names(0, 3),
    };
    futures_executor::block_on(cbrd::execute_group_intent(
        &mut owner,
        &PolicyAt::new(COMMUNITY, policy()),
        create,
        false,
        128,
    ))
    .unwrap();
    assert!(owner.snapshot.members(&[1; 32]).is_ok());
}

fn only(member: &str) -> BTreeSet<String> {
    BTreeSet::from([member.to_owned()])
}

fn block<T>(future: impl std::future::Future<Output = T>) -> T {
    futures_executor::block_on(future)
}

fn circle_proposal(actor: &mut Owner, group: u8, members: BTreeSet<String>) -> cbrd::GroupProposal {
    let policy = PolicyAt::new(COMMUNITY, policy());
    let command = Command::Create {
        id: [group; 32],
        members,
    };
    block(cbrd::propose_group_command(actor, &policy, command, false)).unwrap()
}

/// Deliver the invitation as the text of a conversation message and return
/// the member's decision text.
fn answer(
    invitee: &mut Owner,
    from: &str,
    text: &str,
    accept: bool,
) -> Result<cbrd::GroupMessage, Error> {
    let policy = PolicyAt::new(COMMUNITY, policy());
    let message = cbrd::GroupMessage::from_text(text)?;
    let invitation = block(cbrd::Invitation::receive(invitee, &policy, from, message))?;
    block(invitation.answer(invitee, accept, false))
}

#[test]
fn a_circle_needs_each_member_to_answer_for_themselves_before_it_exists() {
    let mut m0 = Owner::new("m0", only("m0"));
    let mut m1 = Owner::new("m1", only("m1"));
    let mut m2 = Owner::new("m2", only("m2"));
    let mut proposal = circle_proposal(&mut m0, 1, names(0, 3));
    assert_eq!(
        proposal.awaiting(),
        &BTreeSet::from(["m1".into(), "m2".into()])
    );
    let policy = PolicyAt::new(COMMUNITY, policy());
    // Only the actor's own consent exists; the request cannot be committed.
    assert!(
        block(cbrd::commit_group_proposal(
            &mut m0, &policy, &proposal, 128
        ))
        .is_err()
    );

    let text = proposal.invitation().to_text().unwrap();
    for (from, owner) in [("m1", &mut m1), ("m2", &mut m2)] {
        let reply = answer(owner, "m0", &text, true).unwrap();
        proposal.admit(from, reply, 1_000_150).unwrap();
    }
    assert!(proposal.complete());
    let views = block(cbrd::commit_group_proposal(
        &mut m0, &policy, &proposal, 128,
    ))
    .unwrap()
    .views;
    assert_eq!(views.len(), 1);
}

#[test]
fn one_decline_or_a_replayed_wrong_or_foreign_answer_never_completes_a_group() {
    let mut m0 = Owner::new("m0", only("m0"));
    let mut m1 = Owner::new("m1", only("m1"));
    let mut m2 = Owner::new("m2", only("m2"));
    let mut proposal = circle_proposal(&mut m0, 1, names(0, 3));
    let text = proposal.invitation().to_text().unwrap();
    let yes = answer(&mut m1, "m0", &text, true).unwrap();

    // A consent is accepted from its own member only, and only once.
    assert!(proposal.admit("m2", yes.clone(), 1_000_150).is_err());
    proposal.admit("m1", yes.clone(), 1_000_150).unwrap();
    assert!(proposal.admit("m1", yes, 1_000_150).is_err());

    // A consent for another operation or another command does not count.
    let mut other = circle_proposal(&mut Owner::new("m0", only("m0")), 9, names(0, 3));
    let stray = answer(&mut m2, "m0", &other.invitation().to_text().unwrap(), true).unwrap();
    assert!(proposal.admit("m2", stray, 1_000_150).is_err());
    let _ = &mut other;

    // A decline is final for this proposal.
    let no = answer(&mut m2, "m0", &text, false).unwrap();
    proposal.admit("m2", no, 1_000_150).unwrap();
    assert!(proposal.declined() && !proposal.complete());
    let policy = PolicyAt::new(COMMUNITY, policy());
    assert!(
        block(cbrd::commit_group_proposal(
            &mut m0, &policy, &proposal, 128
        ))
        .is_err()
    );
}

#[test]
fn an_invitation_is_refused_from_a_stranger_for_a_non_member_or_when_stale() {
    let mut m0 = Owner::new("m0", only("m0"));
    let proposal = circle_proposal(&mut m0, 1, names(0, 3));
    let text = proposal.invitation().to_text().unwrap();
    // Not sent by the actor named in the request.
    assert!(answer(&mut Owner::new("m1", only("m1")), "m2", &text, true).is_err());
    // The local member is not a consenting party.
    assert!(answer(&mut Owner::new("m7", only("m7")), "m0", &text, true).is_err());
    // The actor cannot invite itself.
    assert!(answer(&mut Owner::new("m0", only("m0")), "m0", &text, true).is_err());
    // Stale: the receiver's clock is far beyond the consent window.
    let mut late = Owner::new("m1", only("m1"));
    late.clock += 10_000;
    assert!(answer(&mut late, "m0", &text, true).is_err());
    // Wrong version and unknown fields are refused.
    assert!(
        cbrd::GroupMessage::from_text(&text.replace("\"version\":1", "\"version\":2")).is_err()
    );
    assert!(
        cbrd::GroupMessage::from_text(
            "{\"kind\":\"decline\",\"version\":1,\"operation\":[],\"member\":\"x\",\"extra\":1}"
        )
        .is_err()
    );
}

#[test]
fn nobody_can_be_added_or_removed_without_the_member_answering() {
    let mut m0 = Owner::new("m0", only("m0"));
    // Create carries every member: the actor alone cannot sign for them.
    let proposal = circle_proposal(&mut m0, 1, names(0, 3));
    let policy = PolicyAt::new(COMMUNITY, policy());
    assert!(proposal.awaiting().contains("m1"));
    assert!(
        block(cbrd::commit_group_proposal(
            &mut m0, &policy, &proposal, 128
        ))
        .is_err()
    );
}

fn invitation_for(invitee: &mut Owner, from: &str, text: &str) -> cbrd::Invitation {
    let policy = PolicyAt::new(COMMUNITY, policy());
    let message = cbrd::GroupMessage::from_text(text).unwrap();
    block(cbrd::Invitation::receive(invitee, &policy, from, message)).unwrap()
}

#[test]
fn a_created_group_carries_each_members_signed_key_package_and_hands_out_one_welcome() {
    let policy = PolicyAt::new(COMMUNITY, policy());
    let mut m0 = Owner::new("m0", only("m0"));
    let mut m1 = Owner::new("m1", only("m1"));
    let mut m2 = Owner::new("m2", only("m2"));
    for owner in [&mut m0, &mut m1, &mut m2] {
        owner.mls = true;
    }
    let mut proposal = circle_proposal(&mut m0, 1, names(0, 3));
    let text = proposal.invitation().to_text().unwrap();
    let mut invitations = vec![];
    for (from, owner) in [("m1", &mut m1), ("m2", &mut m2)] {
        let invitation = invitation_for(owner, "m0", &text);
        let reply = block(invitation.answer(owner, true, false)).unwrap();
        // The package is part of the signed consent, tied to this group.
        let cbrd::GroupMessage::Consent { consent, .. } = &reply else {
            panic!("a consent")
        };
        assert!(consent.key_package.starts_with(from.as_bytes()));
        assert!(!consent.key_package.is_empty());
        proposal.admit(from, reply, 1_000_150).unwrap();
        invitations.push((from, invitation));
    }
    let committed = block(cbrd::commit_group_proposal(
        &mut m0, &policy, &proposal, 128,
    ))
    .unwrap();
    // The actor built the group from exactly the others' signed packages.
    assert_eq!(m0.packages_seen.len(), 2);
    let welcome = committed.welcome.expect("an MLS group has a Welcome");

    // Each member joins from the Welcome the actor sent; nobody else can.
    let (_, one) = &invitations[0];
    assert!(
        block(one.join(&mut m2, &policy, "m0", welcome.clone(), 128)).is_err(),
        "another member's invitation does not join"
    );
    assert!(
        block(one.join(&mut m1, &policy, "m2", welcome.clone(), 128)).is_err(),
        "only the actor's Welcome counts"
    );
    for ((_, invitation), owner) in invitations.iter().zip([&mut m1, &mut m2]) {
        let (views, _) =
            block(invitation.join(owner, &policy, "m0", welcome.clone(), 128)).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(owner.joined_with.as_deref(), Some(&b"welcome"[..]));
    }
}

#[test]
fn a_swapped_key_package_breaks_the_consent_and_the_group_is_not_created() {
    let policy = PolicyAt::new(COMMUNITY, policy());
    let mut m0 = Owner::new("m0", only("m0"));
    let mut m1 = Owner::new("m1", only("m1"));
    let mut m2 = Owner::new("m2", only("m2"));
    for owner in [&mut m0, &mut m1, &mut m2] {
        owner.mls = true;
    }
    let mut proposal = circle_proposal(&mut m0, 1, names(0, 3));
    let text = proposal.invitation().to_text().unwrap();
    for (from, owner) in [("m1", &mut m1), ("m2", &mut m2)] {
        let mut reply = answer(owner, "m0", &text, true).unwrap();
        if let (true, cbrd::GroupMessage::Consent { consent, .. }) = (from == "m2", &mut reply) {
            consent.key_package = b"attacker".to_vec();
        }
        proposal.admit(from, reply, 1_000_150).unwrap();
    }
    assert!(
        block(cbrd::commit_group_proposal(
            &mut m0, &policy, &proposal, 128
        ))
        .is_err()
    );
    assert!(m0.packages_seen.is_empty());
}

#[test]
fn every_signer_attaches_its_own_locator_and_the_joiner_reads_them_from_the_consents() {
    let policy = PolicyAt::new(COMMUNITY, policy());
    let mut m0 = Owner::new("m0", only("m0"));
    let mut m1 = Owner::new("m1", only("m1"));
    let mut m2 = Owner::new("m2", only("m2"));
    for owner in [&mut m0, &mut m1, &mut m2] {
        owner.mls = true;
    }
    m0.held.insert("m0".into(), b"handle-0".to_vec());
    m1.held.insert("m1".into(), b"handle-1".to_vec());
    m2.held.insert("m2".into(), b"handle-2".to_vec());
    let mut proposal = circle_proposal(&mut m0, 1, names(0, 3));
    let text = proposal.invitation().to_text().unwrap();
    let mut invitations = vec![];
    for (from, owner) in [("m1", &mut m1), ("m2", &mut m2)] {
        let invitation = invitation_for(owner, "m0", &text);
        let reply = block(invitation.answer(owner, true, false)).unwrap();
        proposal.admit(from, reply, 1_000_150).unwrap();
        invitations.push(invitation);
    }
    let welcome = block(cbrd::commit_group_proposal(
        &mut m0, &policy, &proposal, 128,
    ))
    .unwrap()
    .welcome
    .unwrap();
    block(invitations[1].join(&mut m2, &policy, "m0", welcome, 128)).unwrap();
    // m2 got the locators the others attached to their own consents (and its
    // own); nobody else can supply one.
    for (member, handle) in [("m0", &b"handle-0"[..]), ("m1", &b"handle-1"[..])] {
        assert_eq!(m2.provided.get(member).map(Vec::as_slice), Some(handle));
    }
    assert!(!m2.provided.contains_key("stranger"));
}
