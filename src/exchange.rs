//! Automatic, give-first exchange of profile keys between two members' devices.
//!
//! Keys travel only from the person to the person, inside the authenticated peer
//! channel owned by Mesh and Vault, never through the Forum or any of our servers.
//! The owner releases its key only when all of these hold at once: both current
//! publications verify under the current policy, both members' rules and blocks
//! accept each other, the requester already proved a key that opens its exact
//! full profile, and the offer is fresh and unused. There is no manual approval.
//! A requester also sends its key only to a member its own rules accept.
//!
//! These functions are synchronous and run inside the owner's Keys custody
//! callback; the owner persists the returned nonce and wrapped key atomically.
use crate::{Board, Error, Input, ReadContext, Verification};
use cpfl::PortableCodec;
use serde::{Deserialize, Serialize};

/// Largest serialized peer message accepted before parsing.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Vault owner of cached peer keys (one wrapped key per peer and revision).
pub const PEER_KEY_OWNER: &str = "board.peers";

/// Key for a cached peer key: the peer's member identifier and revision.
pub fn peer_key_slot(member: &str, revision: u64) -> Vec<u8> {
    let mut slot = member.as_bytes().to_vec();
    slot.push(0);
    slot.extend_from_slice(&revision.to_be_bytes());
    slot
}

/// Borrowed current owners for one exchange step. `custody` comes from
/// `Keys::with_profile_custody`; the context grants nothing by itself.
pub struct ExchangeContext<'a, B: cwst::backend::Backend> {
    pub read: &'a ReadContext<'a, B>,
    pub custody: &'a cnvl::Custodian<'a>,
}

/// The requester's opening message: the public binding offer and the requester's
/// own key sent first. Send only inside the peer channel.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub offer: Vec<u8>,
    pub transfer: Vec<u8>,
}

/// The owner's answer. A refusal carries only the failing field names that the
/// requester may learn; an acceptance carries the owner's key for the requester.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Release {
        nonce: [u8; 32],
        transfer: Vec<u8>,
    },
    Refuse {
        nonce: [u8; 32],
        fields: Vec<String>,
    },
}

impl Request {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Rejected)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Rejected);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::Rejected)
    }
}
impl Reply {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Rejected)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Rejected);
        }
        serde_json::from_slice(bytes).map_err(|_| Error::Rejected)
    }
    fn nonce(&self) -> [u8; 32] {
        match self {
            Self::Release { nonce, .. } | Self::Refuse { nonce, .. } => *nonce,
        }
    }
}

/// The owner's decision on one request. `notice` is for the owner only: it
/// carries the requester's full profile (the look-back) and every reason.
pub struct Answer {
    pub reply: Reply,
    /// Replay identifier. Adopt it with the outgoing reply in one Store commit.
    pub nonce: [u8; 32],
    pub notice: Notice,
}

/// Owner-side record of one decision, with full reasons.
pub struct Notice {
    pub requester: String,
    pub requester_profile: cshm::Profile,
    pub accepted: bool,
    pub failures: cgrd::MatchResult,
}

/// A peer's private profile, opened with a key its owner released to us.
pub struct Opened {
    pub owner: String,
    pub revision: u64,
    pub profile: cshm::Profile,
    /// Encrypted under this device's Envelope custody; store it at
    /// `PEER_KEY_OWNER` / `peer_key_slot(owner, revision)` in the Vault Store.
    pub wrapped_key: Vec<u8>,
}

fn bundle_of(publication: &[u8]) -> Result<cgrd::Bundle, Error> {
    let publication = cpfl::Publication::from_bytes(publication).map_err(|_| Error::Rejected)?;
    serde_json::from_slice(&publication.public_bundle).map_err(|_| Error::Rejected)
}

fn recipient<'a>(
    bundle: &'a cgrd::Bundle,
    member: &str,
    verification: &Verification<'_>,
    contact: &dyn Fn(&str) -> cshm::ContactCheck,
) -> Result<cgrd::VerifiedRecipient<'a>, Error> {
    cgrd::verify_recipient_with_contact(
        bundle,
        member,
        verification.policy,
        verification.signed_schema,
        contact,
    )
    .map_err(|_| Error::Rejected)
}

fn own_key<'k, B: cwst::backend::Backend>(
    context: &ExchangeContext<'k, B>,
    verified: &cpfl::VerifiedPublication,
) -> Result<cnvl::ReadKey<'k>, Error> {
    let wrapped = context
        .read
        .store
        .read(
            "profile.keys",
            &verified.transcript().revision.to_be_bytes(),
        )
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::Unavailable)?;
    context
        .custody
        .restore(
            verified.context(),
            &cnvl::WrappedReadKey::from_bytes(wrapped).map_err(|_| Error::Rejected)?,
        )
        .map_err(|_| Error::Rejected)
}

impl<T: clnk::Transport, R> Board<T, R> {
    /// Requester: build the opening message for `peer`. Refuses unless both
    /// members' rules accept each other now, so a key never goes to someone the
    /// member's own rules exclude. `nonce` must come from runtime CSPRNG custody
    /// and be journalled before the message is sent; `seconds` is the offer life.
    pub fn request_keys<B: cwst::backend::Backend>(
        &mut self,
        context: &ExchangeContext<'_, B>,
        peer: Input<'_>,
        nonce: [u8; 32],
        seconds: u64,
    ) -> Result<Request, Error> {
        let contact = |text: &str| (context.read.contact)(text);
        self.with_committed(context.read, |_, own, verification| {
            let now = verification.policy.policy.now;
            let pair =
                csrh::recheck(own, peer, verification, &contact).map_err(|_| Error::Rejected)?;
            if !pair.decision().is_match() {
                return Err(Error::Rejected);
            }
            let deadline = now.checked_add(seconds).ok_or(Error::Rejected)?;
            let offer =
                cxch::Offer::new(&pair, nonce, now, deadline).map_err(|_| Error::Rejected)?;
            let (own_bundle, peer_bundle) = (bundle_of(own.bytes)?, bundle_of(peer.bytes)?);
            let sender = recipient(&own_bundle, own.member, verification, &contact)?;
            let receiver = recipient(&peer_bundle, peer.member, verification, &contact)?;
            let binding = cnvl::TransferContext::new(
                own.bytes,
                peer.bytes,
                pair.requester().transcript().revision,
                pair.owner().transcript().revision,
                nonce,
            )
            .map_err(|_| Error::Rejected)?;
            let transfer = own_key(context, pair.requester())?
                .release(&sender, &receiver, &binding)
                .and_then(|transfer| transfer.to_bytes())
                .map_err(|_| Error::Rejected)?;
            Ok(Request {
                offer: offer.to_bytes(),
                transfer,
            })
        })
    }

    /// Owner: decide a request automatically from the rules. The requester's key
    /// is consumed and dropped on every path; a refusal reveals only the failing
    /// field names. `seen` is the replay journal in the Vault's encrypted Store.
    pub fn answer_request<B: cwst::backend::Backend>(
        &mut self,
        context: &ExchangeContext<'_, B>,
        request: &Request,
        requester: Input<'_>,
        seen: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<Answer, Error> {
        let contact = |text: &str| (context.read.contact)(text);
        self.with_committed(context.read, |_, own, verification| {
            let now = verification.policy.policy.now;
            if request.offer.len() > cxch::MAX_OFFER_BYTES {
                return Err(Error::Rejected);
            }
            let offer =
                cxch::Offer::from_bytes(&request.offer, now).map_err(|_| Error::Rejected)?;
            let nonce = offer.nonce();
            if seen(&nonce) {
                return Err(Error::Rejected);
            }
            let transfer =
                cnvl::KeyTransfer::from_bytes(&request.transfer).map_err(|_| Error::Rejected)?;
            let inspection = cxch::inspect_transfer(
                &offer,
                (requester, own),
                verification,
                &transfer,
                context.custody,
                &contact,
            )
            .map_err(|_| Error::Rejected)?;
            let accepted = inspection.decision().is_match();
            let reply = if accepted {
                let pair = csrh::recheck(requester, own, verification, &contact)
                    .map_err(|_| Error::Rejected)?;
                let (own_bundle, requester_bundle) =
                    (bundle_of(own.bytes)?, bundle_of(requester.bytes)?);
                let sender = recipient(&own_bundle, own.member, verification, &contact)?;
                let receiver =
                    recipient(&requester_bundle, requester.member, verification, &contact)?;
                let binding = cnvl::TransferContext::new(
                    own.bytes,
                    requester.bytes,
                    pair.owner().transcript().revision,
                    pair.requester().transcript().revision,
                    nonce,
                )
                .map_err(|_| Error::Rejected)?;
                let transfer = own_key(context, pair.owner())?
                    .release(&sender, &receiver, &binding)
                    .and_then(|transfer| transfer.to_bytes())
                    .map_err(|_| Error::Rejected)?;
                Reply::Release { nonce, transfer }
            } else {
                Reply::Refuse {
                    nonce,
                    fields: inspection.decision().requester_fields(),
                }
            };
            Ok(Answer {
                reply,
                nonce,
                notice: Notice {
                    requester: requester.member.to_owned(),
                    requester_profile: inspection.requester_profile().clone(),
                    accepted,
                    failures: inspection.decision().clone(),
                },
            })
        })
    }

    /// Requester: open the owner's private profile from its released key.
    /// `nonce` is the journalled offer nonce; a reply for another offer, or a
    /// refusal, opens nothing. A refusal returns only the failing field names.
    pub fn open_reply<B: cwst::backend::Backend>(
        &mut self,
        context: &ExchangeContext<'_, B>,
        nonce: [u8; 32],
        reply: &Reply,
        owner: Input<'_>,
    ) -> Result<Result<Opened, Vec<String>>, Error> {
        if reply.nonce() != nonce {
            return Err(Error::Rejected);
        }
        let (transfer, nonce) = match reply {
            Reply::Refuse { fields, .. } => return Ok(Err(fields.clone())),
            Reply::Release { transfer, nonce } => (transfer, *nonce),
        };
        let contact = |text: &str| (context.read.contact)(text);
        self.with_committed(context.read, |_, own, verification| {
            let pair =
                csrh::recheck(own, owner, verification, &contact).map_err(|_| Error::Rejected)?;
            // A key from a member our own rules exclude is never accepted.
            if !pair.decision().is_match() {
                return Err(Error::Rejected);
            }
            let (owner_bundle, own_bundle) = (bundle_of(owner.bytes)?, bundle_of(own.bytes)?);
            let sender = recipient(&owner_bundle, owner.member, verification, &contact)?;
            let receiver = recipient(&own_bundle, own.member, verification, &contact)?;
            let binding = cnvl::TransferContext::new(
                owner.bytes,
                own.bytes,
                pair.owner().transcript().revision,
                pair.requester().transcript().revision,
                nonce,
            )
            .map_err(|_| Error::Rejected)?;
            let transfer = cnvl::KeyTransfer::from_bytes(transfer).map_err(|_| Error::Rejected)?;
            let key = context
                .custody
                .receive(
                    &transfer,
                    &pair.owner().context(),
                    &sender,
                    &receiver,
                    &binding,
                )
                .map_err(|_| Error::Rejected)?;
            let publication =
                cpfl::Publication::from_bytes(owner.bytes).map_err(|_| Error::Rejected)?;
            let profile = cpfl::open_full(
                &publication,
                pair.owner(),
                &key,
                &PortableCodec,
                verification.policy,
                verification.signed_schema,
                &contact,
            )
            .map_err(|_| Error::Rejected)?;
            let wrapped_key = key.wrap().map_err(|_| Error::Rejected)?.as_bytes().to_vec();
            Ok(Ok(Opened {
                owner: owner.member.to_owned(),
                revision: pair.owner().transcript().revision,
                profile,
                wrapped_key,
            }))
        })
    }

    /// Read a peer's private profile from a cached key, rechecking the peer's
    /// current publication and both members' rules first. A cached key opens
    /// only the exact revision it was released for.
    pub fn read_cached_profile<B: cwst::backend::Backend>(
        &mut self,
        context: &ExchangeContext<'_, B>,
        owner: Input<'_>,
    ) -> Result<cshm::Profile, Error> {
        let contact = |text: &str| (context.read.contact)(text);
        self.with_committed(context.read, |_, own, verification| {
            let pair =
                csrh::recheck(own, owner, verification, &contact).map_err(|_| Error::Rejected)?;
            if !pair.decision().is_match() {
                return Err(Error::Rejected);
            }
            let transcript = pair.owner().transcript();
            let wrapped = context
                .read
                .store
                .read(
                    PEER_KEY_OWNER,
                    &peer_key_slot(owner.member, transcript.revision),
                )
                .map_err(|_| Error::Unavailable)?
                .ok_or(Error::Unavailable)?;
            let key = context
                .custody
                .restore(
                    pair.owner().context(),
                    &cnvl::WrappedReadKey::from_bytes(wrapped).map_err(|_| Error::Rejected)?,
                )
                .map_err(|_| Error::Rejected)?;
            let publication =
                cpfl::Publication::from_bytes(owner.bytes).map_err(|_| Error::Rejected)?;
            cpfl::open_full(
                &publication,
                pair.owner(),
                &key,
                &PortableCodec,
                verification.policy,
                verification.signed_schema,
                &contact,
            )
            .map_err(|_| Error::Rejected)
        })
    }
}
