//! The line "vouched for by <handle>" on a member's profile.
//!
//! The endorsement a profile carries proves only that some device signed a
//! statement for this community and member. It is shown only after the caller has
//! verified the sponsor's own bundle through Guard (charter credential), so the
//! signing device is one of that member's authorized devices and the handle is
//! the one the charter certified. Nothing else is ever listed: no graph, no
//! counts, no ids.
use cgrd::VerifiedSponsor;

/// What is shown when the sponsor has left the community.
pub const FORMER_MEMBER: &str = "a former member";

/// What the reader knows about the member holding the endorsement's handle.
pub enum Sponsor<'a> {
    /// A current member, verified by Guard against the charter-signed credential: its
    /// handle and authorized devices come from the charter, never from the endorsement.
    Current(&'a VerifiedSponsor),
    /// The sponsor has left. The devices are the sponsor's lineage as it was at admission,
    /// from a roster the community retained (charter-verified, not taken from the profile).
    Departed(&'a [[u8; 32]]),
    /// Nothing verifiable is known about the handle.
    Unknown,
}

/// The display line for a profile, or `None` when nothing may be shown.
///
/// `endorsement` is the `cvch::Endorsement` wire form read from the profile's
/// signed bundle (`cgrd::vouched_by`). The signing device is always checked against the
/// sponsor's own lineage (`sponsor`), never against the device the endorsement names
/// about itself: a current sponsor shows the handle, a departed sponsor whose retained
/// lineage contains the device shows "a former member", anything else shows nothing.
#[must_use]
pub fn vouched_by_line(
    community: &str,
    member: &str,
    endorsement: &[u8],
    sponsor: Sponsor<'_>,
) -> Option<String> {
    let endorsement = cvch::link::Endorsement::from_bytes(endorsement).ok()?;
    endorsement.verify(community, member).ok()?;
    match sponsor {
        Sponsor::Current(sponsor) => (sponsor.handle == endorsement.handle
            && sponsor.devices.contains(&endorsement.device))
        .then(|| format!("vouched for by {}", sponsor.handle)),
        Sponsor::Departed(devices) => devices
            .contains(&endorsement.device)
            .then(|| format!("vouched for by {FORMER_MEMBER}")),
        Sponsor::Unknown => None,
    }
}
