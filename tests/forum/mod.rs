//! Real issuer signatures, current Charter, Profile, Guard and encrypted storage.
//! Fixture device custody is test setup; no accepting verifier is supplied.
use cgth::cswb::Publication;
use ckmg::passkey::{PrfOutput, store_cipher};
use cpfl::{DeviceSigner, Draft, PortableCodec};
use csgn::{Kind, SecretKey, Signer};
use ed25519_dalek::{Digest, Sha512, Signer as _, SigningKey};
use serde_json::{Value, json};

pub const ORIGIN: &str = "https://forum.example.test";
pub const ACTION: &str = "community.admit";
pub fn clean(_: &str) -> cshm::ContactCheck {
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
pub struct Fixture {
    pub publication: Publication,
    pub device: SigningKey,
    pub store: cwst::Store<cwst::backend::Memory>,
    pub binding: ckmg::Binding,
}
fn schema() -> cshm::Schema {
    serde_json::from_value(json!({"community":"garden","version":1,"public":[],"private":[]}))
        .unwrap()
}
pub fn issuer(now: u64) -> Signer {
    Signer::new("garden", SecretKey::from_seed(&mut [11; 32]), now - 1, 3600).unwrap()
}
fn sign(issuer: &mut Signer, kind: Kind, value: Value, now: u64) -> Vec<u8> {
    issuer
        .sign(kind, &serde_json::to_vec(&value).unwrap(), now, now + 300)
        .unwrap()
}
pub fn feed(now: u64, revision: u64, revoked: Value) -> Value {
    let mut issuer = issuer(now);
    let mut feed =
        json!({"revision":revision,"policy_epoch":2,"key_ring":issuer.key_ring().to_cbor()});
    let manifest = json!({"purpose":"cplc.trust.v1","community":"garden","revision":revision,"policy_epoch":2,"key_ring":issuer.key_ring().to_cbor(),"schema_version":1});
    feed["manifest"] = json!(sign(&mut issuer, Kind::SettingsSnapshot, manifest, now));
    for (name, kind, content) in [
        (
            "settings",
            Kind::SettingsSnapshot,
            json!({"forum.heartbeat_ms":3000,"forum.lease_ms":10000,"forum.minimum_client_version":"0.1.0","forum.room_passes_per_epoch":4,"action/community.admit":{"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]}}),
        ),
        ("schema", Kind::SchemaSnapshot, json!(schema())),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema(),"changes":null}]}),
        ),
        ("communities", Kind::CommunitiesSnapshot, json!(["garden"])),
        ("revocations", Kind::RevocationListSnapshot, revoked),
    ] {
        feed[name] = json!(sign(
            &mut issuer,
            kind,
            json!({"community":"garden","revision":revision,"policy_epoch":2,"content":content}),
            now
        ));
    }
    feed
}
impl Fixture {
    pub async fn new(member: &str, revision: u64, now: u64) -> Self {
        let mut issuer = issuer(now);
        let mut charter = cchr::Charter::new(cchr::Configuration {
            origin: "https://identity.example.test".into(),
            community: "garden".into(),
            key_ring: issuer.key_ring().to_cbor(),
            minimum_revision: 1,
            ring_revision: 0,
        })
        .unwrap();
        charter
            .install(
                &serde_json::to_vec(&feed(now, 1, json!({"members":[],"devices":[]}))).unwrap(),
                now,
            )
            .unwrap();
        let mut device = Device(SigningKey::from_bytes(&[13; 32]));
        let credential = sign(
            &mut issuer,
            Kind::Credential,
            json!(cgrd::Credential {
                purpose: cgrd::CredentialPurpose::CommunityCredentialV2,
                issuance_action: "community.admit".into(),
                community: "garden".into(),
                member: member.into(),
                handle: "mountain".into(),
                schema_version: 1,
                policy_epoch: 2,
                gates: vec![],
                pins: vec![],
                devices: vec![device.public_key()],
            }),
            now,
        );
        let draft = Draft::new(
            member.into(),
            cshm::Profile {
                community: "garden".into(),
                schema_version: 1,
                public: Default::default(),
                private: Default::default(),
            },
        )
        .unwrap();
        let cipher = store_cipher(&PrfOutput::from_bytes(&[3; 32]).unwrap(), "garden").unwrap();
        let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
            .await
            .unwrap();
        let current = charter.current(now).unwrap();
        let policy = current.admission_policy(ACTION, now, 300).unwrap();
        let signed_schema = current.publication(cchr::Kind::Schema).signed_bytes();
        // Real maintained conversion of this test device; production custody is
        // lent only by current Keys, never constructed from a request body.
        let hpke: [u8; 32] = Sha512::digest(device.0.as_bytes())[..32]
            .try_into()
            .unwrap();
        let custody =
            cnvl::Custodian::from_keys(&hpke, &[44; 32], "garden", member, device.public_key())
                .unwrap();
        draft
            .prepare_publication(
                &credential,
                &policy,
                signed_schema,
                revision,
                1,
                vec![1],
                0,
                &mut device,
                &custody,
                &PortableCodec,
                &clean,
            )
            .unwrap()
            .commit_publication(
                &mut store,
                cpfl::Validation {
                    policy,
                    signed_schema,
                    contact: &clean,
                },
                [1; 32],
                vec![],
            )
            .await
            .unwrap();
        let signed = store.load_pending().unwrap()[0].bytes.clone();
        let ciphertext = cpfl::Publication::from_bytes(&signed).unwrap().envelope;
        Self {
            publication: Publication { signed, ciphertext },
            device: device.0,
            store,
            binding: ckmg::Binding::new("garden", member).unwrap(),
        }
    }
}
