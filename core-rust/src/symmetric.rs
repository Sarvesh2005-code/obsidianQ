//! Symmetric cryptographic primitives for ML-KEM
//! Wraps SHA3 and SHAKE functions from the `sha3` crate.

use sha3::{Sha3_256, Sha3_512, Shake128, Shake256, Digest};
pub use sha3::digest::{ExtendableOutput, XofReader, Update};

/// Create an active XOF reader for SHAKE-128
pub fn xof_state(seed: &[u8; 32], x: u8, y: u8) -> impl XofReader {
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, seed);
    Update::update(&mut hasher, &[x, y]);
    hasher.finalize_xof()
}

/// Hash H (SHA3-256)
pub fn hash_h(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Update::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hash G (SHA3-512)
pub fn hash_g(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Update::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// KDF (SHAKE-256)
pub fn kdf(input: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; len];
    reader.read(&mut out);
    out
}

/// PRF (SHAKE-256)
pub fn prf(key: &[u8; 32], nonce: u8, len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, key);
    Update::update(&mut hasher, &[nonce]);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; len];
    reader.read(&mut out);
    out
}

/// Standalone XOF function (SHAKE-128)
pub fn xof_absorb_squeeze(seed: &[u8; 32], x: u8, y: u8, len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, seed);
    Update::update(&mut hasher, &[x, y]);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; len];
    reader.read(&mut out);
    out
}
