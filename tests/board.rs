//! Real issuer/device signatures, Profile preparation, encrypted checkpoint and
//! Guard matching. Test signing custody is not production G3 or forum evidence.
use cbrd::{Board, Error};
use ckmg::{
    SystemEntropy,
    passkey::{PrfOutput, store_cipher},
};
use cpfl::{DeviceSigner, Draft, PortableCodec};
use csgn::{Kind, SecretKey, Signer};
use csrh::{Input, Verification, recheck};
use cxch::Offer;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
macro_rules! shared {
    ($name:ident, $body:block) => {
        #[cfg(not(target_arch="wasm32"))]
        #[test]
        fn $name() { futures_executor::block_on(async $body); }
        #[cfg(target_arch="wasm32")]
        #[wasm_bindgen_test::wasm_bindgen_test]
        async fn $name() $body
    };
}
struct Device(SigningKey);
impl DeviceSigner for Device {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&mut self, bytes: &[u8]) -> Result<[u8; 64], cpfl::Error> {
        Ok(self.0.sign(bytes).to_bytes())
    }
}
fn clean(_: &str) -> cshm::ContactCheck {
    cshm::ContactCheck::Clear
}
fn schema() -> cshm::Schema {
    serde_json::from_value(json!({
    "community":"garden","version":1,
    "public":[{"id":"age","label":"Age","kind":{"type":"integer","min":18,"max":120},"required":true,"filterable":true,"change_preset":"stable","no_contact_details":false}],
    "private":[{"id":"secret","label":"Secret","kind":{"type":"yes_no"},"required":true,"filterable":false,"change_preset":"occasional","no_contact_details":false}]
})).unwrap()
}
struct Fixture {
    cipher: ckmg::passkey::StoreCipher,
    wrapped: Vec<u8>,
    wire: Vec<u8>,
    keys: csgn::KeyRing,
    settings: Vec<u8>,
    schema: Vec<u8>,
    revocations: Vec<u8>,
}
impl Fixture {
    async fn new(member: &str, age: u64, rules: Vec<cgrd::Rule>) -> Self {
        let mut device = Device(SigningKey::from_bytes(&[age as u8; 32]));
        let mut draft = Draft::new(
            member.into(),
            cshm::Profile {
                community: "garden".into(),
                schema_version: 1,
                public: [("age".into(), json!(age))].into(),
                private: [("secret".into(), json!(true))].into(),
            },
        )
        .unwrap();
        draft.set_rules(rules).unwrap();
        let pins = draft
            .prepare_pins(&schema(), &clean, &mut SystemEntropy)
            .unwrap();
        let mut issuer =
            Signer::new("garden", SecretKey::from_seed(&mut [11; 32]), 1000, 10000).unwrap();
        let credential = cgrd::Credential {
            community: "garden".into(),
            member: member.into(),
            handle: "mountain".into(),
            schema_version: 1,
            policy_epoch: 2,
            gates: vec![],
            pins,
            devices: vec![device.public_key()],
        };
        let mut sign = |kind, value: serde_json::Value| {
            issuer
                .sign(kind, &serde_json::to_vec(&value).unwrap(), 1000, 2000)
                .unwrap()
        };
        let credential = sign(Kind::Credential, serde_json::to_value(credential).unwrap());
        let signed_schema = sign(
            Kind::SchemaSnapshot,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":schema()}),
        );
        let settings = sign(
            Kind::SettingsSnapshot,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":{"action/admission":{"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]}}}),
        );
        let revocations = sign(
            Kind::RevocationListSnapshot,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":{"members":[],"devices":[]}}),
        );
        let mut fixture = Self {
            cipher: store_cipher(&PrfOutput::from_bytes(&[3; 32]).unwrap(), "garden").unwrap(),
            wrapped: vec![],
            wire: vec![],
            keys: issuer.key_ring().clone(),
            schema: signed_schema,
            settings,
            revocations,
        };
        let cipher = store_cipher(&PrfOutput::from_bytes(&[3; 32]).unwrap(), "garden").unwrap();
        let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
            .await
            .unwrap();
        draft
            .prepare_publication(
                &credential,
                &fixture.policy(),
                &fixture.schema,
                1,
                1,
                vec![1],
                0,
                &mut device,
                &cipher,
                &PortableCodec,
                &mut SystemEntropy,
                &clean,
            )
            .unwrap()
            .commit_publication(
                &mut store,
                cpfl::Validation {
                    policy: fixture.policy(),
                    signed_schema: &fixture.schema,
                    contact: &clean,
                },
                [1; 32],
                vec![],
            )
            .await
            .unwrap();
        fixture.wire = store.load_pending().unwrap()[0].bytes.clone();
        fixture.wrapped = store
            .read("profile.keys", &1u64.to_be_bytes())
            .unwrap()
            .unwrap()
            .to_vec();
        fixture
    }
    fn key(&self) -> cnvl::ReadKey {
        let publication = cpfl::Publication::from_bytes(&self.wire).unwrap();
        let verified =
            cpfl::verify_publication(&publication, &self.policy(), &self.schema, 1, &clean)
                .unwrap();
        cnvl::ReadKey::unwrap(&self.cipher, verified.context(), &self.wrapped).unwrap()
    }
    fn policy(&self) -> cgrd::PublishedPolicy<'_> {
        cgrd::PublishedPolicy {
            policy: cgrd::Policy {
                community: "garden",
                keys: &self.keys,
                now: 1100,
                minimum_epoch: 2,
                minimum_settings_revision: 1,
                minimum_schema_revision: 1,
                maximum_snapshot_age: 300,
                settings: &self.settings,
            },
            revocations: &self.revocations,
            minimum_revocations_revision: 1,
            action: "admission",
        }
    }
    fn input<'a>(&'a self, member: &'a str) -> Input<'a> {
        Input {
            member,
            minimum_revision: 1,
            bytes: &self.wire,
        }
    }
}
// Only transport refusal is supplied; all profile/Guard/encryption logic is real.
struct Offline;
impl clnk::Transport for Offline {
    async fn post(&self, _: &str, _: Vec<u8>) -> Result<Vec<u8>, clnk::ErrorCode> {
        Err(clnk::ErrorCode::Transport)
    }
}
shared!(one_link_and_owner_scopes_are_preserved, {
    let mut board = Board::new(
        "garden".into(),
        clnk::Link::new(Offline).with_anonymous_rooms(Offline),
    )
    .unwrap();
    assert_eq!(board.community(), "garden");
    assert_eq!(board.status().connection, clnk::State::Disconnected);
    assert_eq!(board.status().groups, cbrd::Availability::Unavailable);
    assert_eq!(board.status().rooms, cbrd::Availability::Unavailable);
    assert!(
        board
            .connect(clnk::ChallengeInput {
                credential: vec![1]
            })
            .await
            .is_err()
    );
    board.disconnect();
    assert_eq!(board.status().connection, clnk::State::Disconnected);
    for community in [String::new(), "x".repeat(257)] {
        assert!(matches!(
            Board::new(community, clnk::Link::new(Offline)),
            Err(Error::Scope)
        ));
    }
    let alice = Fixture::new("alice", 34, vec![]).await;
    let bob = Fixture::new("bob", 50, vec![]).await;
    let policy = alice.policy();
    let verification = Verification {
        policy: &policy,
        signed_schema: &alice.schema,
    };
    let pair = board
        .recheck(
            alice.input("alice"),
            bob.input("bob"),
            &verification,
            &clean,
        )
        .unwrap();
    assert!(pair.decision().is_match());
    let offer = Offer::new(&pair, [8; 32], 1100, 1200).unwrap();
    assert!(
        board
            .inspect(
                &offer,
                (alice.input("alice"), bob.input("bob")),
                &verification,
                alice.key(),
                &clean
            )
            .unwrap()
            .decision()
            .is_match()
    );
    assert!(matches!(
        board.inspect(
            &offer,
            (alice.input("alice"), bob.input("bob")),
            &verification,
            bob.key(),
            &clean
        ),
        Err(Error::Rejected)
    ));
    assert!(matches!(
        board.recheck(
            alice.input("wrong"),
            bob.input("bob"),
            &verification,
            &clean
        ),
        Err(Error::Rejected)
    ));
    let foreign = Board::new("other".into(), clnk::Link::new(Offline)).unwrap();
    assert!(matches!(
        foreign.recheck(
            alice.input("alice"),
            bob.input("bob"),
            &verification,
            &clean
        ),
        Err(Error::Scope)
    ));
    assert!(matches!(
        foreign.inspect(
            &offer,
            (alice.input("alice"), bob.input("bob")),
            &verification,
            alice.key(),
            &clean
        ),
        Err(Error::Scope)
    ));
    let pair = recheck(
        alice.input("alice"),
        bob.input("bob"),
        &verification,
        &clean,
    )
    .unwrap();
    assert_eq!(
        pair.decision(),
        &cgrd::matches(pair.requester().participant(), pair.owner().participant())
    );
});

shared!(
    changed_signed_rules_and_expiry_are_rechecked_without_cached_results,
    {
        let board = Board::new("garden".into(), clnk::Link::new(Offline)).unwrap();
        let alice = Fixture::new("alice", 34, vec![]).await;
        let bob = Fixture::new("bob", 50, vec![]).await;
        let alice_blocking = Fixture::new(
            "alice",
            34,
            vec![cgrd::Rule::Block {
                member: "bob".into(),
            }],
        )
        .await;
        let bob_blocking = Fixture::new(
            "bob",
            50,
            vec![cgrd::Rule::Block {
                member: "alice".into(),
            }],
        )
        .await;
        let policy = alice.policy();
        let verification = Verification {
            policy: &policy,
            signed_schema: &alice.schema,
        };
        assert!(
            board
                .recheck(
                    alice.input("alice"),
                    bob.input("bob"),
                    &verification,
                    &clean
                )
                .unwrap()
                .decision()
                .is_match()
        );
        for (requester, owner) in [(&alice_blocking, &bob), (&alice, &bob_blocking)] {
            assert!(
                !board
                    .recheck(
                        requester.input("alice"),
                        owner.input("bob"),
                        &verification,
                        &clean
                    )
                    .unwrap()
                    .decision()
                    .is_match()
            );
            assert!(
                board
                    .recheck(
                        alice.input("alice"),
                        bob.input("bob"),
                        &verification,
                        &clean
                    )
                    .unwrap()
                    .decision()
                    .is_match()
            );
            assert_eq!(board.status().connection, clnk::State::Disconnected);
            assert_eq!(board.status().groups, cbrd::Availability::Unavailable);
            assert_eq!(board.status().rooms, cbrd::Availability::Unavailable);
        }
        let mut expired_policy = alice.policy();
        expired_policy.policy.now = 2000;
        let expired = Verification {
            policy: &expired_policy,
            signed_schema: &alice.schema,
        };
        assert!(matches!(
            board.recheck(alice.input("alice"), bob.input("bob"), &expired, &clean),
            Err(Error::Rejected)
        ));
        assert!(
            board
                .recheck(
                    alice.input("alice"),
                    bob.input("bob"),
                    &verification,
                    &clean
                )
                .unwrap()
                .decision()
                .is_match()
        );
        assert_eq!(board.status().connection, clnk::State::Disconnected);
        assert_eq!(board.status().groups, cbrd::Availability::Unavailable);
        assert_eq!(board.status().rooms, cbrd::Availability::Unavailable);
    }
);

// Link maintained profiling support only into the instrumented test binary.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}
