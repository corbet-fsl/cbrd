//! Own profile and own rules, published as one signed bundle.
//!
//! The Board composes; every authority stays with its owner. Profile signs and
//! seals, Envelope generates the profile key, Guard admits, Vault commits. This
//! module only assembles the inputs: the member's answers, the member's own rules
//! plus one never-match rule per blocked member, and the next revision number
//! derived from the committed publication (never chosen by the caller).
use crate::{Board, Error, ReadContext};
use cpfl::{Candidate, DeviceSigner, Draft, PortableCodec};

/// What the member edits. The community, revision, keys and signatures are not
/// inputs: the community comes from the answers and must equal the Board's.
pub struct Edit {
    /// All answers, public and private, for the current schema.
    pub profile: cshm::Profile,
    /// The member's own rules. Block rules are added from Contacts, not here.
    pub rules: Vec<cgrd::Rule>,
    /// Opaque Mesh descriptor for peer-to-peer reachability (bounded by Profile).
    pub reachability: Vec<u8>,
    /// The sponsor's signed endorsement as the newcomer's device received it
    /// (`cvch::Endorsement` wire form), or `None`. It is a system field, not an
    /// answer: it is published only while the community's current settings keep
    /// `voucher.sponsor_visible` on, and dropped from the next publication when
    /// they do not (one-way: it never appears for a member who has none).
    pub vouched_by: Option<Vec<u8>>,
}

/// Settings key that lets the sponsor's handle appear on a member's profile.
pub const SPONSOR_VISIBLE: &str = "voucher.sponsor_visible";

/// Borrowed current owners for one preparation. Obtain `custody` and the signer
/// together from `Keys::with_profile_custody`, and `credential` from the admitted
/// member's signed community credential; none is accepted from a public action.
pub struct PublishContext<'a, B: cwst::backend::Backend> {
    pub read: &'a ReadContext<'a, B>,
    pub custody: &'a cnvl::Custodian<'a>,
    /// A freshly issued community credential (first publication, or after a
    /// restricted-field change). `None` re-uses the credential inside the
    /// committed publication, so ordinary edits need no new admission.
    pub credential: Option<&'a [u8]>,
}

/// Block rules for the members Contacts currently blocks, deduplicated. Blocks
/// travel inside the signed bundle as never-match rules (full hiding).
pub fn block_rules(blocked: &[String]) -> Vec<cgrd::Rule> {
    let mut seen = std::collections::BTreeSet::new();
    blocked
        .iter()
        .filter(|member| seen.insert((*member).clone()))
        .map(|member| cgrd::Rule::Block {
            member: member.clone(),
        })
        .collect()
}

impl<T: clnk::Transport, R> Board<T, R> {
    /// Check a prepared candidate against the CURRENT policy, synchronously, in
    /// the same borrowed-trust callback that prepared it. The result holds no
    /// policy borrow, so the owner can await the durable write afterwards.
    pub fn authorize_profile<B: cwst::backend::Backend>(
        &self,
        read: &ReadContext<'_, B>,
        candidate: Candidate,
    ) -> Result<cpfl::Authorized, Error> {
        if read.binding.community() != self.community || read.charter.community() != self.community
        {
            return Err(Error::Scope);
        }
        let now = self.link.now_ms().map_err(|_| Error::Unavailable)? / 1000;
        let policy = read
            .charter
            .admission_policy(
                read.policy.admission_action,
                now,
                read.policy.maximum_snapshot_age,
            )
            .map_err(|_| Error::Rejected)?;
        candidate
            .authorize(cpfl::Validation {
                policy,
                signed_schema: read.charter.publication(cchr::Kind::Schema).signed_bytes(),
                contact: read.contact,
            })
            .map_err(|_| Error::Rejected)
    }

    /// Prepare the next publication: one new revision, a fresh profile key sealed
    /// by Envelope, both projections signed by the credential-authorized device
    /// and re-admitted by Guard before anything is returned. Nothing is stored or
    /// sent; the owner commits the candidate atomically with `commit_profile`.
    ///
    /// A restricted-field change needs a fresh credential (new pin) first;
    /// without one Guard refuses admission and this returns `Rejected`.
    pub fn prepare_profile<B: cwst::backend::Backend>(
        &self,
        context: &PublishContext<'_, B>,
        signer: &mut impl DeviceSigner,
        edit: Edit,
        blocked: &[String],
    ) -> Result<Candidate, Error> {
        let read = context.read;
        if read.binding.community() != self.community
            || read.charter.community() != self.community
            || edit.profile.community != self.community
            || !read.store.is_scope(&self.community)
        {
            return Err(Error::Scope);
        }
        if read.policy.admission_action.is_empty() || read.policy.maximum_snapshot_age == 0 {
            return Err(Error::Rejected);
        }
        let now = self.link.now_ms().map_err(|_| Error::Unavailable)? / 1000;
        let policy = || {
            read.charter
                .admission_policy(
                    read.policy.admission_action,
                    now,
                    read.policy.maximum_snapshot_age,
                )
                .map_err(|_| Error::Rejected)
        };
        let signed_schema = read.charter.publication(cchr::Kind::Schema).signed_bytes();
        let contact = |text: &str| (read.contact)(text);
        // The revision floor is the newest committed publication, validated under
        // the current policy. A missing one means this is the first publication.
        let previous = cpfl::load_current_committed(
            read.store,
            read.binding,
            cpfl::Validation {
                policy: policy()?,
                signed_schema,
                contact: read.contact,
            },
        )
        .map_err(|_| Error::Rejected)?;
        let (revision, expected_checkpoint) = match &previous {
            Some(committed) => (
                committed
                    .verified()
                    .transcript()
                    .revision
                    .checked_add(1)
                    .ok_or(Error::Rejected)?,
                committed.checkpoint(),
            ),
            None => (1, read.store.version().map_err(|_| Error::Unavailable)?),
        };
        let previous_credential = match &previous {
            Some(committed) => Some(
                serde_json::from_slice::<cgrd::Bundle>(&committed.publication().public_bundle)
                    .ok()
                    .and_then(|bundle| {
                        serde_json::from_slice::<cgrd::BundleContent>(&bundle.payload).ok()
                    })
                    .map(|content| content.credential)
                    .ok_or(Error::Rejected)?,
            ),
            None => None,
        };
        let credential = context
            .credential
            .or(previous_credential.as_deref())
            .ok_or(Error::Unavailable)?;
        let mut draft = match read
            .store
            .read("profile", b"draft")
            .map_err(|_| Error::Unavailable)?
        {
            Some(bytes) => Draft::from_checkpoint(bytes).map_err(|_| Error::Rejected)?,
            None => Draft::new(read.binding.member().to_owned(), edit.profile.clone())
                .map_err(|_| Error::Rejected)?,
        };
        draft.edit(edit.profile).map_err(|_| Error::Rejected)?;
        // Fail closed: a missing or mistyped setting hides the sponsor.
        let visible = read
            .charter
            .settings(now)
            .ok()
            .and_then(|settings| settings.content.get(SPONSOR_VISIBLE))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        draft
            .set_vouched_by(edit.vouched_by.filter(|_| visible))
            .map_err(|_| Error::Rejected)?;
        let mut rules = edit.rules;
        rules.retain(|rule| !matches!(rule, cgrd::Rule::Block { .. }));
        rules.extend(block_rules(blocked));
        draft.set_rules(rules).map_err(|_| Error::Rejected)?;
        // Every publication seals under a fresh profile key, so the key
        // generation tracks the revision.
        draft
            .prepare_publication(
                credential,
                &policy()?,
                signed_schema,
                revision,
                revision,
                edit.reachability,
                expected_checkpoint,
                signer,
                context.custody,
                &PortableCodec,
                &contact,
            )
            .map_err(|_| Error::Rejected)
    }
}

/// Persist an authorized candidate with the Vault's writable Store. The Store
/// version fence applies; a failed or uncertain write returns no publication, so
/// reopen and reconcile before retry.
pub async fn commit_profile<B: cwst::backend::Backend>(
    authorized: cpfl::Authorized,
    store: &mut cwst::Store<B>,
    operation: [u8; 32],
) -> Result<u64, Error> {
    authorized
        .commit(store, operation, vec![])
        .await
        .map_err(|_| Error::Rejected)
}
