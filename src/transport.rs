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

/// The epoch-derived keys of one room: an AEAD key and a separate nonce key,
/// both exporter secrets of the same MLS epoch under distinct labels. Debug
/// output never shows them.
#[derive(Clone, PartialEq, Eq)]
pub struct TransportKey {
    aead: [u8; 32],
    nonce: [u8; 32],
}

impl std::fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportKey(..)")
    }
}

impl TransportKey {
    pub fn new(aead: [u8; 32], nonce: [u8; 32]) -> Self {
        Self { aead, nonce }
    }

    /// The keys Threads derived from the epoch's exporter secrets.
    pub fn from_keys(keys: &cthr::TransportKeys) -> Self {
        Self::new(keys.aead, keys.nonce)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&self.aead.into())
    }

    /// The synthetic nonce: a keyed hash, under the separate nonce key, of the
    /// whole additional data and the whole plaintext (each length-prefixed).
    fn synthetic_nonce(&self, room: &[u8; 16], plain: &[u8]) -> [u8; NONCE] {
        let mut hash = blake3::Hasher::new_keyed(&self.nonce);
        hash.update(b"cbrd.room.transport.nonce.v1\0");
        hash.update(&(room.len() as u64).to_le_bytes());
        hash.update(room);
        hash.update(&(plain.len() as u64).to_le_bytes());
        hash.update(plain);
        let mut nonce = [0; NONCE];
        nonce.copy_from_slice(&hash.finalize().as_bytes()[..NONCE]);
        nonce
    }

    /// Seal `plain` for `room` (the additional data). The nonce is synthetic
    /// (see `synthetic_nonce`), so an exact retry of the same frame yields the
    /// same bytes and the library needs no random source.
    ///
    /// The relay can therefore recognise exact retransmissions: two identical
    /// wrapped frames mean one identical plaintext, and a different plaintext
    /// gives a different nonce (barring a 96-bit hash collision). It learns
    /// nothing beyond that equality: the nonce is a keyed hash under a key the
    /// relay never holds, and that key is not the AEAD key.
    pub fn wrap(&self, room: &[u8; 16], plain: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.synthetic_nonce(room, plain);
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
    pub transport: cthr::TransportKeys,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TransportKey {
        TransportKey::new([7; 32], [9; 32])
    }

    #[test]
    fn a_wrapped_frame_opens_only_with_the_key_and_room() {
        let key = key();
        let wrapped = key.wrap(&[1; 16], b"external commit and companion").unwrap();
        assert!(!wrapped.windows(8).any(|w| w == b"external"));
        assert_eq!(
            key.unwrap(&[1; 16], &wrapped).unwrap(),
            b"external commit and companion"
        );
        assert!(key.unwrap(&[2; 16], &wrapped).is_none());
        assert!(
            TransportKey::new([8; 32], [9; 32])
                .unwrap(&[1; 16], &wrapped)
                .is_none()
        );
        let mut broken = wrapped.clone();
        *broken.last_mut().unwrap() ^= 1;
        assert!(key.unwrap(&[1; 16], &broken).is_none());
        assert!(key.unwrap(&[1; 16], &wrapped[..20]).is_none());
        assert_eq!(format!("{key:?}"), "TransportKey(..)");
    }

    #[test]
    fn an_equal_frame_gives_equal_bytes() {
        let key = key();
        let first = key.wrap(&[1; 16], b"the same frame").unwrap();
        assert_eq!(key.wrap(&[1; 16], b"the same frame").unwrap(), first);
        // The same plaintext in another room is another frame (the room is the
        // additional data and the nonce covers it).
        assert_ne!(key.wrap(&[2; 16], b"the same frame").unwrap(), first);
    }

    #[test]
    fn a_different_frame_gives_a_different_nonce() {
        let key = key();
        let nonce_of = |room: &[u8; 16], plain: &[u8]| {
            key.wrap(room, plain).unwrap()[..NONCE].to_vec()
        };
        let base = nonce_of(&[1; 16], b"frame one");
        assert_ne!(base, nonce_of(&[1; 16], b"frame two"));
        // One flipped bit anywhere changes the nonce: the hash covers the full plaintext.
        let mut long = vec![0u8; 4096];
        let first = nonce_of(&[1; 16], &long);
        *long.last_mut().unwrap() ^= 1;
        assert_ne!(first, nonce_of(&[1; 16], &long));
        // The additional data (the room) is covered too.
        assert_ne!(base, nonce_of(&[2; 16], b"frame one"));
        // A frame and its prefix never share a nonce.
        assert_ne!(nonce_of(&[1; 16], b"ab"), nonce_of(&[1; 16], b"a"));
    }

    #[test]
    fn the_nonce_key_is_not_the_aead_key() {
        // Changing only the nonce key changes the nonce but the frame still
        // opens with the AEAD key alone; changing only the AEAD key makes the
        // frame unopenable while the nonce stays the same.
        let plain = b"separate keys";
        let base = key().wrap(&[1; 16], plain).unwrap();
        let other_nonce = TransportKey::new([7; 32], [10; 32]).wrap(&[1; 16], plain).unwrap();
        let other_aead = TransportKey::new([8; 32], [9; 32]).wrap(&[1; 16], plain).unwrap();
        assert_ne!(base[..NONCE], other_nonce[..NONCE]);
        assert_eq!(base[..NONCE], other_aead[..NONCE]);
        assert_eq!(key().unwrap(&[1; 16], &other_nonce).unwrap(), plain);
        assert!(key().unwrap(&[1; 16], &other_aead).is_none());
    }
}
