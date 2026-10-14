//! The display line shows a sponsor only after signature and lineage agree.
use cbrd::{FORMER_MEMBER, Sponsor, vouched_by_line};
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
        Sponsor::Current(&sponsor(&key, "sponsorname")),
    );
    assert_eq!(line.as_deref(), Some("vouched for by sponsorname"));
    // Wrong community or member: the signature does not hold.
    let s = sponsor(&key, "sponsorname");
    assert_eq!(vouched_by_line("other", "alice", &wire, Sponsor::Current(&s)), None);
    assert_eq!(vouched_by_line("garden", "bob", &wire, Sponsor::Current(&s)), None);
    // A genuine signature from a device that is not the sponsor's.
    let forged = endorsed(&other, "garden", "alice", "sponsorname");
    assert_eq!(vouched_by_line("garden", "alice", &forged, Sponsor::Current(&s)), None);
    // A handle that differs from the charter-certified one.
    assert_eq!(
        vouched_by_line(
            "garden",
            "alice",
            &wire,
            Sponsor::Current(&sponsor(&key, "someoneelse"))
        ),
        None
    );
    // Garbage is never shown.
    assert_eq!(
        vouched_by_line("garden", "alice", &[1, 2, 3], Sponsor::Current(&s)),
        None
    );
    // Unverifiable: no line at all, never a guess.
    assert_eq!(vouched_by_line("garden", "alice", &wire, Sponsor::Unknown), None);
}

#[test]
fn a_departed_sponsor_reads_former_member_only_through_the_retained_lineage() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let other = SigningKey::from_bytes(&[4; 32]);
    let wire = endorsed(&key, "garden", "alice", "sponsorname");
    let lineage = [key.verifying_key().to_bytes()];
    let gone = vouched_by_line("garden", "alice", &wire, Sponsor::Departed(&lineage)).unwrap();
    assert_eq!(gone, format!("vouched for by {FORMER_MEMBER}"));
    assert!(!gone.contains("sponsorname"));
    // A self-signed endorsement from a device outside the sponsor's lineage is not "a former member".
    let forged = endorsed(&other, "garden", "alice", "sponsorname");
    assert_eq!(vouched_by_line("garden", "alice", &forged, Sponsor::Departed(&lineage)), None);
    // Wrong subject still fails.
    assert_eq!(vouched_by_line("garden", "bob", &wire, Sponsor::Departed(&lineage)), None);
}
