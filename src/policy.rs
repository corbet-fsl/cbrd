//! Groups policy projection from the original authenticated Rulebook snapshot.
//!
//! Charter hands product owners the borrowed `crbk::Snapshot`; this module is
//! the Board owner's canonical projection of the `groups.*`, `seats.*` and
//! `waves.*` keys into the Groups library's `Policy`. A missing, mistyped or
//! out-of-range key refuses; no value is defaulted here. The final check is
//! Groups' own `Policy::validate`.
use cgrp::{Band, DAY, Policy, PolicySource, SeatFormats};
use serde_json::Value;

type Result<T> = std::result::Result<T, cgrp::Error>;

fn value<'a>(snapshot: &'a crbk::Snapshot, key: &str) -> Result<&'a Value> {
    snapshot.content.get(key).ok_or(cgrp::Error::Policy)
}
fn number(snapshot: &crbk::Snapshot, key: &str) -> Result<u64> {
    value(snapshot, key)?.as_u64().ok_or(cgrp::Error::Policy)
}
fn small(snapshot: &crbk::Snapshot, key: &str) -> Result<u16> {
    u16::try_from(number(snapshot, key)?).map_err(|_| cgrp::Error::Policy)
}
fn float(snapshot: &crbk::Snapshot, key: &str) -> Result<f64> {
    value(snapshot, key)?.as_f64().ok_or(cgrp::Error::Policy)
}
fn flag(snapshot: &crbk::Snapshot, key: &str) -> Result<bool> {
    value(snapshot, key)?.as_bool().ok_or(cgrp::Error::Policy)
}
/// Wave credits are signed in whole Waves; Groups counts quarter units. Any
/// value that is not an exact multiple of a quarter refuses.
fn quarters(snapshot: &crbk::Snapshot, key: &str) -> Result<u16> {
    let scaled = float(snapshot, key)? * 4.0;
    if !scaled.is_finite() || scaled < 0.0 || scaled.fract() != 0.0 || scaled > f64::from(u16::MAX)
    {
        return Err(cgrp::Error::Policy);
    }
    Ok(scaled as u16)
}
fn days(snapshot: &crbk::Snapshot, key: &str) -> Result<u64> {
    number(snapshot, key)?
        .checked_mul(DAY)
        .ok_or(cgrp::Error::Policy)
}

/// Project the signed settings of `valid_until`'s epoch into a Groups policy.
pub fn project(snapshot: &crbk::Snapshot, valid_until: u64) -> Result<Policy> {
    let bands: Vec<Band> = serde_json::from_value(value(snapshot, "groups.curve")?.clone())
        .map_err(|_| cgrp::Error::Policy)?;
    let bands: [Band; 9] = bands.try_into().map_err(|_| cgrp::Error::Policy)?;
    Ok(Policy {
        epoch: snapshot.policy_epoch,
        valid_until,
        cap: small(snapshot, "groups.cap")?,
        circle_max: small(snapshot, "groups.circle_max")?,
        ingroup_max: small(snapshot, "groups.ingroup_max")?,
        shrink_public: small(snapshot, "groups.shrink_public")?,
        shrink_ingroup: small(snapshot, "groups.shrink_ingroup")?,
        open_seconds: days(snapshot, "groups.open_days")?,
        fork_cooldown: days(snapshot, "groups.fork_cooldown_days")?,
        retarget_cooldown: days(snapshot, "groups.retarget_cooldown_days")?,
        listing_wait: number(snapshot, "groups.fork_listing_wait_h")?
            .checked_mul(3_600)
            .ok_or(cgrp::Error::Policy)?,
        split_public_min: small(snapshot, "groups.split_public_min")?,
        bands,
        seats: SeatFormats {
            enabled: flag(snapshot, "seats.enabled")?,
            refill_per_day: float(snapshot, "seats.refill_per_day")?,
            capacity: float(snapshot, "seats.capacity")?,
            initial: float(snapshot, "seats.initial")?,
            minimum: float(snapshot, "seats.w_min")?,
            small: float(snapshot, "seats.w_small")?,
            large: float(snapshot, "seats.w_big")?,
            low: small(snapshot, "seats.n_lo")?,
            high: small(snapshot, "seats.n_hi")?,
            tau: float(snapshot, "seats.tau")?,
            epoch_days: small(snapshot, "seats.epoch_days")?,
            quantum: float(snapshot, "seats.quantum")?,
            warning_days: small(snapshot, "seats.shed_warning_days")?,
        },
        suggest_at: small(snapshot, "groups.suggest.threshold")?,
        pressure_at: small(snapshot, "groups.suggest.hard")?,
        modularity: float(snapshot, "groups.suggest.modularity")?,
        overlap: float(snapshot, "groups.suggest.jaccard")?,
        suggestion_cooldown: days(snapshot, "groups.suggest.cooldown_days")?,
        decline_cooldown: days(snapshot, "groups.suggest.decline_cooldown_days")?,
        reciprocity_enabled: flag(snapshot, "groups.reciprocity_credit.enabled")?,
        welcome_quarters: quarters(snapshot, "waves.welcome_credit")?,
        introduction_quarters: quarters(snapshot, "waves.introduction_credit")?,
        week_cap_quarters: quarters(snapshot, "waves.group_credit_week_cap")?,
    })
}

/// The borrowed Rulebook snapshot of the current verified Charter, with that
/// Charter's deadline. It authenticates nothing itself: construct it only from
/// `VerifiedCharter::settings(now)` and `VerifiedCharter::valid_until()`.
pub struct SettingsPolicy<'a> {
    snapshot: &'a crbk::Snapshot,
    valid_until: u64,
}
impl<'a> SettingsPolicy<'a> {
    pub fn new(snapshot: &'a crbk::Snapshot, valid_until: u64) -> Self {
        Self {
            snapshot,
            valid_until,
        }
    }
}
impl PolicySource for SettingsPolicy<'_> {
    fn current(&self, community: &str, now: u64) -> Result<Policy> {
        if self.snapshot.community != community {
            return Err(cgrp::Error::Authority);
        }
        let policy = project(self.snapshot, self.valid_until)?;
        policy.validate(now)?;
        Ok(policy)
    }
}
