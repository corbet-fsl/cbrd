//! Group write side through the Board: real Groups decisions, real ed25519
//! consents, fake device directory, contacts and checkpoint store.
use cbrd::cgrp::{
    self, Band, Candidate, Command, Commit, CommitFuture, CommittedEffect, DAY, Effect, Error, Id,
    Notification, Persistence, Policy, PolicySource, SeatFormats, Snapshot,
};
use cbrd::{BoardAuthority, Contacts, Devices, GroupOwner, PortFuture, Seeds, Signed};
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

struct Fixed;
impl PolicySource for Fixed {
    fn current(&self, community: &str, _: u64) -> cgrp::Result<Policy> {
        if community != COMMUNITY {
            return Err(Error::Authority);
        }
        Ok(policy())
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
struct Standing(bool);
impl Seeds for Standing {
    fn authorized(&self, _: &str, _: &Id, _: u64) -> cgrp::Result<()> {
        if self.0 {
            Ok(())
        } else {
            Err(Error::Authority)
        }
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
    snapshot: Snapshot,
    store: Checkpoint,
    clock: u64,
    operations: u8,
    /// Members who answered the invitation; others refuse.
    answered: BTreeSet<String>,
    fail_clock: bool,
}
impl Owner {
    fn new(answered: BTreeSet<String>) -> Self {
        let snapshot = Snapshot::empty(COMMUNITY.into());
        Self {
            store: Checkpoint(snapshot.revision()),
            snapshot,
            clock: 1_000_000,
            operations: 0,
            answered,
            fail_clock: false,
        }
    }
}
impl GroupOwner for Owner {
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

fn run(
    owner: &mut Owner,
    seeds: bool,
    command: Command,
    actor: &str,
    visible: bool,
) -> cgrp::Result<(Snapshot, Vec<CommittedEffect>)> {
    let authority = BoardAuthority::new(Directory, Everyone, Standing(seeds));
    futures_executor::block_on(cbrd::execute_group_command(
        owner, &Fixed, &authority, command, actor, visible, 128,
    ))
}

#[test]
fn a_circle_is_created_described_and_left_with_every_member_consenting() {
    let mut owner = Owner::new(names(0, 3));
    let create = Command::Create {
        id: [1; 32],
        members: names(0, 3),
        seed: false,
    };
    let (snapshot, effects) = run(&mut owner, false, create, "m0", false).unwrap();
    assert_eq!(snapshot.members(&[1; 32]).unwrap(), &names(0, 3));
    assert!(matches!(effects[0].event(), Effect::Membership { .. }));

    let describe = Command::Describe {
        group: [1; 32],
        name: "Hike".into(),
        description: "Walks".into(),
    };
    run(&mut owner, false, describe, "m1", false).unwrap();
    let (snapshot, _) = run(
        &mut owner,
        false,
        Command::Leave { group: [1; 32] },
        "m2",
        false,
    )
    .unwrap();
    assert_eq!(snapshot.members(&[1; 32]).unwrap(), &names(0, 2));
    assert_eq!(owner.store.0, snapshot.revision());
    run(&mut owner, false, Command::Tick, "m0", false).unwrap();
}

#[test]
fn a_command_without_every_required_answer_changes_nothing() {
    let mut owner = Owner::new(names(0, 2));
    let create = Command::Create {
        id: [1; 32],
        members: names(0, 3),
        seed: false,
    };
    assert_eq!(
        run(&mut owner, false, create, "m0", false).err().unwrap(),
        Error::Unavailable
    );
    assert_eq!(owner.snapshot.revision(), 0);
    owner.fail_clock = true;
    assert_eq!(
        run(&mut owner, false, Command::Tick, "m0", false)
            .err()
            .unwrap(),
        Error::Clock
    );
}

#[test]
fn joining_a_room_states_the_profile_visibility_consent() {
    let mut owner = Owner::new(names(0, 5));
    let seed = Command::Create {
        id: [2; 32],
        members: names(0, 3),
        seed: true,
    };
    // A standing room needs the Rulebook's authorization and visibility consent.
    assert_eq!(
        run(&mut owner, false, seed.clone(), "m0", true)
            .err()
            .unwrap(),
        Error::Authority
    );
    assert_eq!(
        run(&mut owner, true, seed.clone(), "m0", false)
            .err()
            .unwrap(),
        Error::Authority
    );
    run(&mut owner, true, seed, "m0", true).unwrap();
    let join = Command::Join {
        group: [2; 32],
        member: "m4".into(),
        vouches: BTreeSet::new(),
    };
    assert_eq!(
        run(&mut owner, true, join.clone(), "m4", false)
            .err()
            .unwrap(),
        Error::Authority
    );
    let (snapshot, _) = run(&mut owner, true, join, "m4", true).unwrap();
    assert!(snapshot.members(&[2; 32]).unwrap().contains("m4"));
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
    let authority = BoardAuthority::new(Directory, Everyone, Standing(false));
    let mut consent = cgrp::Consent {
        community: COMMUNITY.into(),
        member: "m0".into(),
        operation: [1; 32],
        policy_epoch: 1,
        command_digest: [2; 32],
        profile_visibility: false,
        valid_until: 10,
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
    assert_eq!(
        authority.seed(COMMUNITY, &[1; 32], 5),
        Err(Error::Authority)
    );
    assert_eq!(cbrd::CONSENT_SECONDS, 3_600);
}
