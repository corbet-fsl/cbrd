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

/// The display line for a profile, or `None` when nothing may be shown.
///
/// `endorsement` is the `cvch::Endorsement` wire form read from the profile's
/// signed bundle (`cgrd::vouched_by`). `sponsor` is the Guard-verified bundle
/// facts of the member holding that handle, looked up by the endorsement's handle;
/// `None` means no current member has it (a departed sponsor).
#[must_use]
pub fn vouched_by_line(
    community: &str,
    member: &str,
    endorsement: &[u8],
    sponsor: Option<&VerifiedSponsor>,
) -> Option<String> {
    let endorsement = cvch::link::Endorsement::from_bytes(endorsement).ok()?;
    endorsement.verify(community, member).ok()?;
    let Some(sponsor) = sponsor else {
        return Some(format!("vouched for by {FORMER_MEMBER}"));
    };
    (sponsor.handle == endorsement.handle && sponsor.devices.contains(&endorsement.device))
        .then(|| format!("vouched for by {}", sponsor.handle))
}
