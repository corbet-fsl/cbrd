//! Production seam for Groups' `Authority`: three narrow ports, no key logic.
//!
//! Groups asks three questions: is this signed consent valid for a currently
//! authorized device of the member, are these two members established
//! contacts, and is an imported parent genuine. The Board owns none of the
//! answers: Keys/Guard answer the first (signature, device certificate chain
//! and revocations), Contacts the second. The third stays refused until
//! Threads supplies original MLS evidence. There are no standing (seed) rooms.
use cgrp::{Authority, Consent, Error, Id, Result};

/// Verifies a member's exact signed statement against that member's current
/// device authority (Guard, certificate chain, revocations).
pub trait Devices {
    fn verify(
        &self,
        community: &str,
        member: &str,
        message: &[u8],
        signature: &[u8],
        authority: &[u8],
        now: u64,
    ) -> Result<()>;
}

/// Established-contact check; blocks and unknown peers refuse.
pub trait Contacts {
    fn established(&self, community: &str, member: &str, contact: &str, now: u64) -> Result<()>;
}

pub struct BoardAuthority<D, C> {
    devices: D,
    contacts: C,
}

impl<D, C> BoardAuthority<D, C> {
    pub fn new(devices: D, contacts: C) -> Self {
        Self { devices, contacts }
    }
}

impl<D: Devices, C: Contacts> Authority for BoardAuthority<D, C> {
    fn consent(&self, consent: &Consent, now: u64) -> Result<()> {
        if consent.valid_until <= now {
            return Err(Error::Authority);
        }
        self.devices.verify(
            &consent.community,
            &consent.member,
            &consent.signing_bytes()?,
            &consent.signature,
            &consent.authority,
            now,
        )
    }
    fn contact(&self, community: &str, member: &str, contact: &str, now: u64) -> Result<()> {
        self.contacts.established(community, member, contact, now)
    }
}
