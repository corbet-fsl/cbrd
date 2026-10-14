//! Room transport encryption for the ordered join frames. The ordering server
//! relays these frames and must learn nothing from them: not the newcomer's
//! pseudonym, not the signed Join request. The key is derived by Threads from
//! the MLS epoch (an exporter secret) and reaches a newcomer inside the sealed
//! room state, so only room members and the newcomer hold it.
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};

const NONCE: usize = 12;
const TAG: usize = 16;

/// The epoch-derived key of one room. Debug output never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct TransportKey([u8; 32]);

impl std::fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportKey(..)")
    }
}

impl TransportKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&self.0.into())
    }

    /// Seal `plain` for `room`. The nonce is synthetic (a keyed hash of room and
    /// plaintext), so an exact retry of the same order yields the same bytes and
    /// the library needs no random source.
    pub fn wrap(&self, room: &[u8; 16], plain: &[u8]) -> Option<Vec<u8>> {
        let mut hash = blake3::Hasher::new_keyed(&self.0);
        hash.update(b"cbrd.room.transport.nonce.v1\0");
        hash.update(room);
        hash.update(plain);
        let mut nonce = [0; NONCE];
        nonce.copy_from_slice(&hash.finalize().as_bytes()[..NONCE]);
        let sealed = self
            .cipher()
            .encrypt(&nonce.into(), Payload { msg: plain, aad: room })
            .ok()?;
        let mut out = Vec::with_capacity(NONCE + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Some(out)
    }

    /// Open one wrapped frame; every failure is the same `None`.
    pub fn unwrap(&self, room: &[u8; 16], wrapped: &[u8]) -> Option<Vec<u8>> {
        if wrapped.len() < NONCE + TAG {
            return None;
        }
        let (nonce, sealed) = wrapped.split_at(NONCE);
        let nonce: [u8; NONCE] = nonce.try_into().ok()?;
        self.cipher()
            .decrypt(&nonce.into(), Payload { msg: sealed, aad: room })
            .ok()
    }
}

/// What a member seals to a newcomer's ephemeral key: the verified parent
/// evidence and the room's transport key for the epoch the newcomer joins from.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomState {
    pub evidence: cthr::ParentEvidence,
    pub transport: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrapped_frame_opens_only_with_the_key_and_room() {
        let key = TransportKey::from_bytes([7; 32]);
        let wrapped = key.wrap(&[1; 16], b"external commit and companion").unwrap();
        assert!(!wrapped.windows(8).any(|w| w == b"external"));
        assert_eq!(
            key.unwrap(&[1; 16], &wrapped).unwrap(),
            b"external commit and companion"
        );
        assert_eq!(key.wrap(&[1; 16], b"external commit and companion").unwrap(), wrapped);
        assert!(key.unwrap(&[2; 16], &wrapped).is_none());
        assert!(TransportKey::from_bytes([8; 32]).unwrap(&[1; 16], &wrapped).is_none());
        let mut broken = wrapped.clone();
        *broken.last_mut().unwrap() ^= 1;
        assert!(key.unwrap(&[1; 16], &broken).is_none());
        assert!(key.unwrap(&[1; 16], &wrapped[..20]).is_none());
        assert_eq!(format!("{key:?}"), "TransportKey(..)");
    }
}
