//! The display line shows a sponsor only after signature and lineage agree.
use cbrd::{FORMER_MEMBER, vouched_by_line};
use cgrd::VerifiedSponsor;
use cvch::link::{Endorsement, endorsement_bytes};
use ed25519_dalek::{Signer, SigningKey};

fn endorsed(key: &SigningKey, community: &str, member: &str, handle: &str) -> Vec<u8> {
    let signature = key.sign(&endorsement_bytes(community, member, handle));
    Endorsement::new(handle, key.verifying_key().to_bytes(), signature.to_bytes())
        .unwrap()
        .to_bytes()
        .unwrap()
}
fn sponsor(key: &SigningKey, handle: &str) -> VerifiedSponsor {
    VerifiedSponsor {
        member: "sponsor-pseudonym".into(),
        handle: handle.into(),
        devices: vec![key.verifying_key().to_bytes()],
    }
}

#[test]
fn a_verified_sponsor_is_named_and_everything_else_is_not() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let other = SigningKey::from_bytes(&[4; 32]);
    let wire = endorsed(&key, "garden", "alice", "sponsorname");
    let line = vouched_by_line(
        "garden",
        "alice",
        &wire,
        Some(&sponsor(&key, "sponsorname")),
    );
    assert_eq!(line.as_deref(), Some("vouched for by sponsorname"));
    // Wrong community or member: the signature does not hold.
    let s = sponsor(&key, "sponsorname");
    assert_eq!(vouched_by_line("other", "alice", &wire, Some(&s)), None);
    assert_eq!(vouched_by_line("garden", "bob", &wire, Some(&s)), None);
    // A genuine signature from a device that is not the sponsor's.
    let forged = endorsed(&other, "garden", "alice", "sponsorname");
    assert_eq!(vouched_by_line("garden", "alice", &forged, Some(&s)), None);
    // A handle that differs from the charter-certified one.
    assert_eq!(
        vouched_by_line(
            "garden",
            "alice",
            &wire,
            Some(&sponsor(&key, "someoneelse"))
        ),
        None
    );
    // Garbage is never shown.
    assert_eq!(
        vouched_by_line("garden", "alice", &[1, 2, 3], Some(&s)),
        None
    );
    // A departed sponsor is only "a former member", never the handle.
    let gone = vouched_by_line("garden", "alice", &wire, None).unwrap();
    assert_eq!(gone, format!("vouched for by {FORMER_MEMBER}"));
    assert!(!gone.contains("sponsorname"));
}
