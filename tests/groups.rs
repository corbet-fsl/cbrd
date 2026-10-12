//! Group write side through the Board: real Groups decisions, real ed25519
//! consents, fake device directory, contacts and checkpoint store.
use cbrd::cgrp::{
    self, Band, Candidate, Command, Commit, CommitFuture, CommittedEffect, DAY, Effect, Error, Id,
    Notification, Persistence, Policy, SeatFormats, Snapshot,
};
use cbrd::{BoardAuthority, Contacts, Devices, GroupOwner, PolicyAt, PortFuture, Seeds, Signed};
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
    me: String,
    authority: BoardAuthority<Directory, Everyone, Standing>,
    snapshot: Snapshot,
    store: Checkpoint,
    clock: u64,
    operations: u8,
    /// Members who answered the invitation; others refuse.
    answered: BTreeSet<String>,
    fail_clock: bool,
}
impl Owner {
    fn new(me: &str, seeds: bool, answered: BTreeSet<String>) -> Self {
        let snapshot = Snapshot::empty(COMMUNITY.into());
        Self {
            me: me.into(),
            authority: BoardAuthority::new(Directory, Everyone, Standing(seeds)),
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

fn as_member(owner: &mut Owner, member: &str, seeds: bool) {
    owner.me = member.into();
    owner.authority = BoardAuthority::new(Directory, Everyone, Standing(seeds));
}

#[test]
fn a_circle_is_created_described_and_left_with_every_member_consenting() {
    let mut owner = Owner::new("m0", false, names(0, 3));
    let create = Command::Create {
        id: [1; 32],
        members: names(0, 3),
        seed: false,
    };
    let snapshot = run(&mut owner, create, false).unwrap();
    assert_eq!(snapshot.members(&[1; 32]).unwrap(), &names(0, 3));

    as_member(&mut owner, "m1", false);
    let describe = Command::Describe {
        group: [1; 32],
        name: "Hike".into(),
        description: "Walks".into(),
    };
    run(&mut owner, describe, false).unwrap();
    as_member(&mut owner, "m2", false);
    let snapshot = run(&mut owner, Command::Leave { group: [1; 32] }, false).unwrap();
    assert_eq!(snapshot.members(&[1; 32]).unwrap(), &names(0, 2));
    assert_eq!(owner.store.0, snapshot.revision());
    as_member(&mut owner, "m0", false);
    run(&mut owner, Command::Tick, false).unwrap();
}

#[test]
fn a_command_without_every_required_answer_changes_nothing() {
    let mut owner = Owner::new("m0", false, names(0, 2));
    let create = Command::Create {
        id: [1; 32],
        members: names(0, 3),
        seed: false,
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
    let mut owner = Owner::new("m0", false, names(0, 5));
    let seed = Command::Create {
        id: [2; 32],
        members: names(0, 3),
        seed: true,
    };
    // A standing room needs the Rulebook's authorization and visibility consent.
    assert_eq!(
        run(&mut owner, seed.clone(), true).err().unwrap(),
        Error::Authority
    );
    as_member(&mut owner, "m0", true);
    assert_eq!(
        run(&mut owner, seed.clone(), false).err().unwrap(),
        Error::Authority
    );
    run(&mut owner, seed, true).unwrap();
    as_member(&mut owner, "m4", true);
    let join = Command::Join {
        group: [2; 32],
        member: "m4".into(),
        vouches: BTreeSet::new(),
    };
    assert_eq!(
        run(&mut owner, join.clone(), false).err().unwrap(),
        Error::Authority
    );
    let snapshot = run(&mut owner, join, true).unwrap();
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
            seed: false,
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
    let mut owner = Owner::new("m0", false, names(0, 3));
    let create = GroupIntent::Create {
        id: [1; 32],
        members: names(0, 3),
        seed: false,
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
