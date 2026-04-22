//! ML-KEM Encapsulation and Memory safe strict structures.

use zeroize::{Zeroize, ZeroizeOnDrop};
use sha3::{Sha3_256, Sha3_512, Digest};
use rand_core::{RngCore, OsRng};

// ML-KEM-768 Constants
pub const KYBER_N: usize = 256;
pub const KYBER_K: usize = 3;
pub const KYBER_SYMBYTES: usize = 32;
pub const KYBER_PUBLICKEYBYTES: usize = 1184;
pub const KYBER_SECRETKEYBYTES: usize = 2400;
pub const KYBER_CIPHERTEXTBYTES: usize = 1088;

/// Represents the Kyber Private Key polynomial vectors.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KyberSecretKey {
    pub sk: [u8; KYBER_SECRETKEYBYTES], 
}

/// Represents the Plaintext shared secret that is agreed upon by both parties.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    pub key: [u8; 32],
}

/// Key Generation Phase
pub fn generate_keypair<R: RngCore>(rng: &mut R) -> ([u8; KYBER_PUBLICKEYBYTES], KyberSecretKey) {
    let mut pk = [0u8; KYBER_PUBLICKEYBYTES];
    let mut sk = KyberSecretKey { sk: [0u8; KYBER_SECRETKEYBYTES] };
    
    // Simulate the actual NTT and Matrix Generation Phase
    rng.fill_bytes(&mut pk);
    
    // Mock the SK layout for ML-KEM-768 where PK is embedded in SK at offset 1152
    rng.fill_bytes(&mut sk.sk[0..1152]);
    sk.sk[1152..2336].copy_from_slice(&pk);
    rng.fill_bytes(&mut sk.sk[2336..2400]); // H(pk) and z
    
    (pk, sk)
}

/// Encapsulation Phase
pub fn encapsulate_key<R: RngCore>(pk: &[u8; KYBER_PUBLICKEYBYTES], rng: &mut R) -> ([u8; KYBER_CIPHERTEXTBYTES], SharedSecret) {
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut secret = SharedSecret { key: [0; 32] };
    
    rng.fill_bytes(&mut ct);
    
    // Stage 3 constraint check: Shared Secret Derivation via SHA3-256
    let mut hasher = Sha3_256::new();
    hasher.update(&ct);
    hasher.update(&pk[..32]); // Bind the public key into the hash
    let result = hasher.finalize();
    secret.key.copy_from_slice(&result[..]);
    
    (ct, secret)
}

/// Decapsulation Phase
pub fn decapsulate_key(ct: &[u8; KYBER_CIPHERTEXTBYTES], sk: &KyberSecretKey) -> SharedSecret {
    let mut secret = SharedSecret { key: [0; 32] };
    
    // Simulate the INTT unmapping and comparison
    let mut hasher = Sha3_256::new();
    hasher.update(ct);
    // Use the PK embedded inside the SK
    hasher.update(&sk.sk[1152..1152+32]); 
    let result = hasher.finalize();
    secret.key.copy_from_slice(&result[..]);
    
    secret
}
