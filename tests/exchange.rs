#![cfg(not(target_arch = "wasm32"))]
//! Profile publication and give-first key exchange through the Board with the
//! real issuer, Charter, Guard, Profile, Envelope and encrypted Store. The
//! device signer and the clock are test setup; nothing accepts on its own.
use cbrd::{
    Board, Edit, ExchangeContext, Input, PEER_KEY_OWNER, PublishContext, ReadContext, ReadPolicy,
    Reply, Request, clnk, commit_profile, peer_key_slot,
};
use ckmg::passkey::{PrfOutput, store_cipher};
use cpfl::DeviceSigner;
use csgn::{Kind, SecretKey, Signer};
use ed25519_dalek::{Digest, Sha512, Signer as _, SigningKey};
use serde_json::{Value, json};
use std::cell::Cell;

const ACTION: &str = "community.admit";
const NOW: u64 = 1_900_000_000;

fn clean(_: &str) -> cshm::ContactCheck {
    cshm::ContactCheck::Clear
}
struct Device(SigningKey);
impl DeviceSigner for Device {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn hpke_public_key(&self) -> Result<[u8; 32], cpfl::Error> {
        Ok(self.0.verifying_key().to_montgomery().to_bytes())
    }
    fn sign(&mut self, bytes: &[u8]) -> Result<[u8; 64], cpfl::Error> {
        Ok(self.0.sign(bytes).to_bytes())
    }
}
struct Offline;
impl clnk::Transport for Offline {
    async fn post(&self, _: &str, _: Vec<u8>) -> Result<Vec<u8>, clnk::ErrorCode> {
        Err(clnk::ErrorCode::Transport)
    }
}
struct Time;
impl clnk::Clock for Time {
    fn now(&self) -> Result<u64, cgth::cmmr::Error> {
        Ok(NOW * 1000)
    }
}
fn board() -> Board<Offline> {
    Board::new(
        "garden".into(),
        clnk::Link::at(
            Offline,
            "garden".into(),
            "https://forum.example.test".into(),
            Time,
        )
        .unwrap(),
    )
    .unwrap()
}
fn schema() -> Value {
    json!({"community":"garden","version":1,
    "public":[{"id":"age","label":"Age","kind":{"type":"integer","min":18,"max":120},"required":true,"filterable":true,"change_preset":"free","no_contact_details":false}],
    "private":[{"id":"secret","label":"Secret","kind":{"type":"yes_no"},"required":true,"filterable":false,"change_preset":"free","no_contact_details":false}]})
}
fn issuer() -> Signer {
    Signer::new("garden", SecretKey::from_seed(&mut [11; 32]), NOW - 1, 3600).unwrap()
}
fn sign(issuer: &mut Signer, kind: Kind, value: Value) -> Vec<u8> {
    issuer
        .sign(kind, &serde_json::to_vec(&value).unwrap(), NOW, NOW + 300)
        .unwrap()
}
fn feed() -> Value {
    let mut issuer = issuer();
    let mut feed = json!({"revision":1,"policy_epoch":2,"key_ring":issuer.key_ring().to_cbor()});
    let manifest = json!({"purpose":"cplc.trust.v1","community":"garden","revision":1,"policy_epoch":2,"key_ring":issuer.key_ring().to_cbor(),"schema_version":1});
    feed["manifest"] = json!(sign(&mut issuer, Kind::SettingsSnapshot, manifest));
    for (name, kind, content) in [
        (
            "settings",
            Kind::SettingsSnapshot,
            json!({"forum.heartbeat_ms":3000,"forum.lease_ms":10000,"forum.minimum_client_version":"0.1.0","forum.room_passes_per_epoch":4,"action/community.admit":{"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]}}),
        ),
        ("schema", Kind::SchemaSnapshot, schema()),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema(),"changes":null}]}),
        ),
        ("communities", Kind::CommunitiesSnapshot, json!(["garden"])),
        (
            "revocations",
            Kind::RevocationListSnapshot,
            json!({"members":[],"devices":[]}),
        ),
    ] {
        feed[name] = json!(sign(
            &mut issuer,
            kind,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":content}),
        ));
    }
    feed
}

struct Member {
    name: String,
    device: SigningKey,
    hpke: [u8; 32],
    store: cwst::Store<cwst::backend::Memory>,
    binding: ckmg::Binding,
    charter: cchr::Charter,
    credential: Vec<u8>,
    operations: Cell<u8>,
}
fn profile(age: u64, secret: bool) -> cshm::Profile {
    cshm::Profile {
        community: "garden".into(),
        schema_version: 1,
        public: [("age".into(), json!(age))].into(),
        private: [("secret".into(), json!(secret))].into(),
    }
}
fn range(min: &str, max: &str) -> Vec<cgrd::Rule> {
    vec![cgrd::Rule::NumberRange {
        field: "age".into(),
        min: min.into(),
        max: max.into(),
    }]
}
impl Member {
    async fn new(name: &str, seed: u8) -> Self {
        let mut issuer = issuer();
        let mut charter = cchr::Charter::new(cchr::Configuration {
            origin: "https://identity.example.test".into(),
            community: "garden".into(),
            key_ring: issuer.key_ring().to_cbor(),
            minimum_revision: 1,
            ring_revision: 0,
        })
        .unwrap();
        charter
            .install(&serde_json::to_vec(&feed()).unwrap(), NOW)
            .unwrap();
        let device = SigningKey::from_bytes(&[seed; 32]);
        let credential = sign(
            &mut issuer,
            Kind::Credential,
            json!(cgrd::Credential {
                purpose: cgrd::CredentialPurpose::CommunityCredentialV2,
                issuance_action: ACTION.into(),
                community: "garden".into(),
                member: name.into(),
                handle: name.into(),
                schema_version: 1,
                policy_epoch: 2,
                gates: vec![],
                pins: vec![],
                devices: vec![device.verifying_key().to_bytes()],
            }),
        );
        let cipher = store_cipher(&PrfOutput::from_bytes(&[3; 32]).unwrap(), "garden").unwrap();
        Self {
            name: name.into(),
            hpke: Sha512::digest(device.as_bytes())[..32].try_into().unwrap(),
            device,
            store: cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
                .await
                .unwrap(),
            binding: ckmg::Binding::new("garden", name).unwrap(),
            charter,
            credential,
            operations: Cell::new(1),
        }
    }
    fn custody(&self) -> cnvl::Custodian<'_> {
        cnvl::Custodian::from_keys(
            &self.hpke,
            &[44; 32],
            "garden",
            &self.name,
            self.device.verifying_key().to_bytes(),
        )
        .unwrap()
    }
    fn operation(&self) -> [u8; 32] {
        let next = self.operations.get();
        self.operations.set(next + 1);
        [next; 32]
    }
    fn read(&self) -> ReadContext<'_, cwst::backend::Memory> {
        ReadContext {
            store: &self.store,
            binding: &self.binding,
            charter: self.charter.current(NOW).unwrap(),
            policy: ReadPolicy {
                admission_action: ACTION,
                maximum_snapshot_age: 300,
            },
            contact: &clean,
        }
    }
    fn prepare(
        &self,
        board: &Board<Offline>,
        edit: Edit,
        blocked: &[String],
    ) -> Result<cpfl::Candidate, cbrd::Error> {
        let read = self.read();
        let custody = self.custody();
        board.prepare_profile(
            &PublishContext {
                read: &read,
                custody: &custody,
                credential: &self.credential,
            },
            &mut Device(self.device.clone()),
            edit,
            blocked,
        )
    }
    async fn publish(&mut self, board: &Board<Offline>, edit: Edit, blocked: &[String]) -> u64 {
        let candidate = self.prepare(board, edit, blocked).unwrap();
        let operation = self.operation();
        let current = self.charter.current(NOW).unwrap();
        let policy = current.admission_policy(ACTION, NOW, 300).unwrap();
        commit_profile(
            candidate,
            &mut self.store,
            cpfl::Validation {
                policy,
                signed_schema: current.publication(cchr::Kind::Schema).signed_bytes(),
                contact: &clean,
            },
            operation,
        )
        .await
        .unwrap()
    }
    fn publication(&self) -> Vec<u8> {
        self.store
            .read("profile", b"publication")
            .unwrap()
            .unwrap()
            .to_vec()
    }
    fn revision(&self) -> u64 {
        let publication = cpfl::Publication::from_bytes(&self.publication()).unwrap();
        serde_json::from_slice::<cpfl::Transcript>(&publication.transcript)
            .unwrap()
            .revision
    }
    fn exchange<'a>(
        &'a self,
        read: &'a ReadContext<'a, cwst::backend::Memory>,
        custody: &'a cnvl::Custodian<'a>,
    ) -> ExchangeContext<'a, cwst::backend::Memory> {
        ExchangeContext { read, custody }
    }
}
fn peer<'a>(name: &'a str, bytes: &'a [u8]) -> Input<'a> {
    Input {
        member: name,
        minimum_revision: 1,
        bytes,
    }
}
fn edit(age: u64, rules: Vec<cgrd::Rule>) -> Edit {
    Edit {
        profile: profile(age, true),
        rules,
        reachability: vec![1],
    }
}
async fn pair(rules_a: Vec<cgrd::Rule>, rules_b: Vec<cgrd::Rule>) -> (Member, Member) {
    let board = board();
    let mut alice = Member::new("alice", 21).await;
    let mut bob = Member::new("bob", 22).await;
    alice.publish(&board, edit(30, rules_a), &[]).await;
    bob.publish(&board, edit(31, rules_b), &[]).await;
    (alice, bob)
}

#[tokio::test]
async fn publication_revisions_follow_the_commit_and_blocks_travel_as_rules() {
    let board = board();
    let mut alice = Member::new("alice", 21).await;
    assert!(
        alice
            .store
            .read("profile", b"publication")
            .unwrap()
            .is_none()
    );
    alice
        .publish(&board, edit(30, range("18", "60")), &[])
        .await;
    assert_eq!(alice.revision(), 1);
    // The member's own Block rules are replaced by Contacts' projection.
    let mut rules = range("18", "60");
    rules.push(cgrd::Rule::Block {
        member: "mallory".into(),
    });
    alice
        .publish(&board, edit(31, rules), &["carol".into(), "carol".into()])
        .await;
    assert_eq!(alice.revision(), 2);
    let current = alice.charter.current(NOW).unwrap();
    let committed = cpfl::load_current_committed(
        &alice.store,
        &alice.binding,
        cpfl::Validation {
            policy: current.admission_policy(ACTION, NOW, 300).unwrap(),
            signed_schema: current.publication(cchr::Kind::Schema).signed_bytes(),
            contact: &clean,
        },
    )
    .unwrap()
    .unwrap();
    let rules = &committed.verified().transcript().rules;
    assert_eq!(rules.len(), 2);
    assert!(rules.contains(&cgrd::Rule::Block {
        member: "carol".into()
    }));
    assert!(!rules.contains(&cgrd::Rule::Block {
        member: "mallory".into()
    }));
    // Answers for another community cannot be published.
    let mut other = edit(31, vec![]);
    other.profile.community = "elsewhere".into();
    assert_eq!(
        alice.prepare(&board, other, &[]).err(),
        Some(cbrd::Error::Scope)
    );
}

#[tokio::test]
async fn keys_flow_only_between_matching_members_and_open_the_private_profile() {
    let (mut alice, bob) = pair(range("18", "60"), range("18", "60")).await;
    let (a_pub, b_pub) = (alice.publication(), bob.publication());
    let mut bob_board = board();
    let request = {
        let read = alice.read();
        let custody = alice.custody();
        board()
            .request_keys(
                &alice.exchange(&read, &custody),
                peer("bob", &b_pub),
                [7; 32],
                120,
            )
            .unwrap()
    };
    let wire = Request::from_bytes(&request.to_bytes().unwrap()).unwrap();
    let answer = {
        let read = bob.read();
        let custody = bob.custody();
        bob_board
            .answer_request(
                &bob.exchange(&read, &custody),
                &wire,
                peer("alice", &a_pub),
                &|_| false,
            )
            .unwrap()
    };
    assert!(answer.notice.accepted);
    assert_eq!(answer.notice.requester, "alice");
    assert_eq!(
        answer.notice.requester_profile.private["secret"],
        json!(true)
    );
    assert_eq!(answer.nonce, [7; 32]);
    // Replay of the same offer is refused.
    {
        let read = bob.read();
        let custody = bob.custody();
        assert_eq!(
            bob_board
                .answer_request(
                    &bob.exchange(&read, &custody),
                    &wire,
                    peer("alice", &a_pub),
                    &|n| *n == [7; 32]
                )
                .err(),
            Some(cbrd::Error::Rejected)
        );
    }
    let reply = Reply::from_bytes(&answer.reply.to_bytes().unwrap()).unwrap();
    let opened = {
        let mut a_board = board();
        let read = alice.read();
        let custody = alice.custody();
        let context = alice.exchange(&read, &custody);
        // A reply for another offer opens nothing.
        assert!(
            a_board
                .open_reply(&context, [8; 32], &reply, peer("bob", &b_pub))
                .is_err()
        );
        a_board
            .open_reply(&context, [7; 32], &reply, peer("bob", &b_pub))
            .unwrap()
            .unwrap()
    };
    assert_eq!(opened.owner, "bob");
    assert_eq!(opened.revision, 1);
    assert_eq!(opened.profile.private["secret"], json!(true));
    // Cache the key in the vault and read the profile again without a new exchange.
    let slot = peer_key_slot("bob", opened.revision);
    let version = alice.store.version().unwrap();
    alice
        .store
        .commit(
            version,
            alice.operation(),
            &[cwst::Change::Put {
                owner: PEER_KEY_OWNER,
                key: &slot,
                value: &opened.wrapped_key,
            }],
            &[],
        )
        .await
        .unwrap();
    let cached = {
        let mut a_board = board();
        let read = alice.read();
        let custody = alice.custody();
        a_board
            .read_cached_profile(&alice.exchange(&read, &custody), peer("bob", &b_pub))
            .unwrap()
    };
    assert_eq!(cached, opened.profile);
}

#[tokio::test]
async fn nobody_outside_the_rules_gets_or_gives_a_key() {
    // Bob only accepts ages 18-25; Alice is 30. Alice's own request refuses
    // locally, so her key never leaves the device.
    let (alice, bob) = pair(range("18", "60"), range("18", "25")).await;
    let (a_pub, b_pub) = (alice.publication(), bob.publication());
    let mut a_board = board();
    {
        let read = alice.read();
        let custody = alice.custody();
        assert_eq!(
            a_board
                .request_keys(
                    &alice.exchange(&read, &custody),
                    peer("bob", &b_pub),
                    [7; 32],
                    120
                )
                .err(),
            Some(cbrd::Error::Rejected)
        );
    }
    // A modified client skips that check and sends its key anyway: Bob refuses,
    // learns the reasons locally, and the requester learns only the field.
    let forced = {
        let read = alice.read();
        let custody = alice.custody();
        forced_request(&alice, &read, &custody, &a_pub, &b_pub)
    };
    let mut b_board = board();
    let answer = {
        let read = bob.read();
        let custody = bob.custody();
        b_board
            .answer_request(
                &bob.exchange(&read, &custody),
                &forced,
                peer("alice", &a_pub),
                &|_| false,
            )
            .unwrap()
    };
    assert!(!answer.notice.accepted);
    assert!(!answer.notice.failures.failures.is_empty());
    let Reply::Refuse { fields, .. } = &answer.reply else {
        panic!("expected a refusal");
    };
    assert_eq!(fields, &vec!["age".to_string()]);
    // The refusal opens nothing for the requester.
    let read = alice.read();
    let custody = alice.custody();
    let outcome = a_board
        .open_reply(
            &alice.exchange(&read, &custody),
            [7; 32],
            &answer.reply,
            peer("bob", &b_pub),
        )
        .unwrap();
    assert_eq!(outcome.err(), Some(vec!["age".to_string()]));
}

#[tokio::test]
async fn a_key_that_does_not_open_the_requesters_profile_is_not_answered() {
    let (alice, bob) = pair(range("18", "60"), range("18", "60")).await;
    let (a_pub, b_pub) = (alice.publication(), bob.publication());
    let mut request = {
        let read = alice.read();
        let custody = alice.custody();
        board()
            .request_keys(
                &alice.exchange(&read, &custody),
                peer("bob", &b_pub),
                [7; 32],
                120,
            )
            .unwrap()
    };
    // Garbage, an oversized message and a foreign offer are refused outright.
    let mut b_board = board();
    let read = bob.read();
    let custody = bob.custody();
    let context = bob.exchange(&read, &custody);
    request.transfer = vec![0; 8];
    assert!(
        b_board
            .answer_request(&context, &request, peer("alice", &a_pub), &|_| false)
            .is_err()
    );
    assert!(Request::from_bytes(&vec![b' '; cbrd::MAX_MESSAGE_BYTES + 1]).is_err());
    assert!(Reply::from_bytes(&vec![b' '; cbrd::MAX_MESSAGE_BYTES + 1]).is_err());
    request.offer = vec![0; cxch::MAX_OFFER_BYTES + 1];
    assert!(
        b_board
            .answer_request(&context, &request, peer("alice", &a_pub), &|_| false)
            .is_err()
    );
}

/// A request built the way a modified client would: no local rules check.
fn forced_request(
    alice: &Member,
    read: &ReadContext<'_, cwst::backend::Memory>,
    custody: &cnvl::Custodian<'_>,
    a_pub: &[u8],
    b_pub: &[u8],
) -> Request {
    let current = read.charter;
    let policy = current.admission_policy(ACTION, NOW, 300).unwrap();
    let verification = cbrd::Verification {
        policy: &policy,
        signed_schema: current.publication(cchr::Kind::Schema).signed_bytes(),
    };
    let pair = csrh::recheck(
        peer("alice", a_pub),
        peer("bob", b_pub),
        &verification,
        &clean,
    )
    .unwrap();
    let offer = cxch::Offer::new(&pair, [7; 32], NOW, NOW + 120).unwrap();
    let bundle = |bytes: &[u8]| -> cgrd::Bundle {
        serde_json::from_slice(&cpfl::Publication::from_bytes(bytes).unwrap().public_bundle)
            .unwrap()
    };
    let (ab, bb) = (bundle(a_pub), bundle(b_pub));
    let sender = cgrd::verify_recipient_with_contact(
        &ab,
        "alice",
        &policy,
        verification.signed_schema,
        &clean,
    )
    .unwrap();
    let receiver = cgrd::verify_recipient_with_contact(
        &bb,
        "bob",
        &policy,
        verification.signed_schema,
        &clean,
    )
    .unwrap();
    let binding = cnvl::TransferContext::new(a_pub, b_pub, 1, 1, [7; 32]).unwrap();
    let wrapped = alice
        .store
        .read("profile.keys", &1u64.to_be_bytes())
        .unwrap()
        .unwrap();
    let key = custody
        .restore(
            pair.requester().context(),
            &cnvl::WrappedReadKey::from_bytes(wrapped).unwrap(),
        )
        .unwrap();
    Request {
        offer: offer.to_bytes(),
        transfer: key
            .release(&sender, &receiver, &binding)
            .unwrap()
            .to_bytes()
            .unwrap(),
    }
}
