//! Sealing the room state to a newcomer's ephemeral key (HPKE base mode,
//! X25519, ChaCha20-Poly1305). Anyone may seal to a public key; what the
//! newcomer opens is untrusted until Threads verifies the evidence inside.
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

const ENC: usize = 32;
/// Largest state a room answer carries (GroupInfo, ratchet tree, evidence).
pub const MAX_STATE_BYTES: usize = 64 * 1024;

fn info(room: &[u8; 16], to: u64) -> Vec<u8> {
    let mut info = b"cbrd.room.state.v1".to_vec();
    info.extend_from_slice(room);
    info.extend_from_slice(&to.to_be_bytes());
    info
}

/// The newcomer's one-time key. Use once; drop after the join.
pub struct JoinKey(<Kem as KemTrait>::PrivateKey);

impl JoinKey {
    /// From 32 fresh random bytes supplied by the caller (cbrd owns no RNG).
    pub fn derive(ikm: &[u8; 32]) -> (Self, [u8; 32]) {
        let (secret, public) = Kem::derive_keypair(ikm);
        let mut key = [0; 32];
        key.copy_from_slice(&public.to_bytes());
        (Self(secret), key)
    }

    /// Open one answer to request `to` of `room`; every failure is the same `None`.
    pub fn open(&self, room: &[u8; 16], to: u64, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() <= ENC || sealed.len() > MAX_STATE_BYTES + ENC + 16 {
            return None;
        }
        let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&sealed[..ENC]).ok()?;
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &self.0,
            &enc,
            &info(room, to),
            &sealed[ENC..],
            &[],
        )
        .ok()
    }
}

/// Seal `state` to the key in request `to` of `room`.
pub fn seal(public_key: &[u8; 32], room: &[u8; 16], to: u64, state: &[u8]) -> Option<Vec<u8>> {
    if state.len() > MAX_STATE_BYTES {
        return None;
    }
    let public = <Kem as KemTrait>::PublicKey::from_bytes(public_key).ok()?;
    let (enc, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &public,
        &info(room, to),
        state,
        &[],
    )
    .ok()?;
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&ciphertext);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_requested_key_room_and_request_open_the_answer() {
        let (key, public) = JoinKey::derive(&[1; 32]);
        let (other, _) = JoinKey::derive(&[2; 32]);
        let sealed = seal(&public, &[3; 16], 7, b"group info and tree").unwrap();
        assert_ne!(&sealed[ENC..], b"group info and tree".as_slice());
        assert_eq!(
            key.open(&[3; 16], 7, &sealed).unwrap(),
            b"group info and tree"
        );
        assert!(other.open(&[3; 16], 7, &sealed).is_none());
        assert!(key.open(&[4; 16], 7, &sealed).is_none());
        assert!(key.open(&[3; 16], 8, &sealed).is_none());
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(key.open(&[3; 16], 7, &altered).is_none());
        assert!(key.open(&[3; 16], 7, &[0; 10]).is_none());
        assert!(seal(&public, &[3; 16], 7, &vec![0; MAX_STATE_BYTES + 1]).is_none());
    }
}
