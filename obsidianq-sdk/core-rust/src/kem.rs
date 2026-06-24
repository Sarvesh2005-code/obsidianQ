//! ML-KEM Encapsulation and Memory safe strict structures.

use zeroize::{Zeroize, ZeroizeOnDrop};
use sha3::{Sha3_256, Sha3_512, Digest};
use rand_core::RngCore;

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
    
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut z);
    
    let mut hasher = Sha3_512::new();
    hasher.update(&d);
    let hash_res = hasher.finalize();
    
    let mut seed = [0u8; 32];
    let mut noiseseed = [0u8; 32];
    seed.copy_from_slice(&hash_res[0..32]);
    noiseseed.copy_from_slice(&hash_res[32..64]);
    
    crate::indcpa::indcpa_keypair((&mut pk[0..crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES]).try_into().unwrap(), (&mut sk.sk[0..crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES]).try_into().unwrap(), &seed, &noiseseed);
    
    // sk = sk || pk || H(pk) || z
    sk.sk[crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES..crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES].copy_from_slice(&pk[0..crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES]);
    
    let mut hasher2 = Sha3_256::new();
    hasher2.update(&pk[0..crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES]);
    let hpk = hasher2.finalize();
    
    sk.sk[crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES..crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES + 32].copy_from_slice(&hpk);
    sk.sk[crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES + 32..crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES + 64].copy_from_slice(&z);
    
    (pk, sk)
}

/// Encapsulation Phase
pub fn encapsulate_key<R: RngCore>(pk: &[u8; KYBER_PUBLICKEYBYTES], rng: &mut R) -> ([u8; KYBER_CIPHERTEXTBYTES], SharedSecret) {
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut secret = SharedSecret { key: [0; 32] };
    
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    
    let mut hasher = Sha3_256::new();
    hasher.update(&m);
    let m = hasher.finalize();
    let mut m_arr = [0u8; 32];
    m_arr.copy_from_slice(&m);
    
    let mut hasher2 = Sha3_256::new();
    hasher2.update(&pk[0..crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES]);
    let hpk = hasher2.finalize();
    
    let mut hasher3 = Sha3_512::new();
    hasher3.update(&m_arr);
    hasher3.update(&hpk);
    let kr = hasher3.finalize();
    
    let mut k = [0u8; 32];
    let mut r = [0u8; 32];
    k.copy_from_slice(&kr[0..32]);
    r.copy_from_slice(&kr[32..64]);
    
    crate::indcpa::indcpa_enc((&mut ct[0..crate::indcpa::KYBER_INDCPA_BYTES]).try_into().unwrap(), &m_arr, (&pk[0..crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES]).try_into().unwrap(), &r);
    
    let mut hasher_kdf = Sha3_256::new();
    hasher_kdf.update(&k);
    let mut hasher_ct = Sha3_256::new();
    hasher_ct.update(&ct);
    hasher_kdf.update(&hasher_ct.finalize());
    let ss = hasher_kdf.finalize();
    
    secret.key.copy_from_slice(&ss);
    
    (ct, secret)
}

/// Decapsulation Phase
pub fn decapsulate_key(ct: &[u8; KYBER_CIPHERTEXTBYTES], sk: &KyberSecretKey) -> SharedSecret {
    let mut secret = SharedSecret { key: [0; 32] };
    
    let mut m_prime = [0u8; 32];
    crate::indcpa::indcpa_dec(&mut m_prime, (&ct[0..crate::indcpa::KYBER_INDCPA_BYTES]).try_into().unwrap(), (&sk.sk[0..crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES]).try_into().unwrap());
    
    let mut hpk = [0u8; 32];
    hpk.copy_from_slice(&sk.sk[crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES..crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES + 32]);
    
    let mut hasher_kr = Sha3_512::new();
    hasher_kr.update(&m_prime);
    hasher_kr.update(&hpk);
    let kr = hasher_kr.finalize();
    
    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_prime.copy_from_slice(&kr[0..32]);
    r_prime.copy_from_slice(&kr[32..64]);
    
    let mut ct_prime = [0u8; KYBER_CIPHERTEXTBYTES];
    let mut pk = [0u8; crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES];
    pk.copy_from_slice(&sk.sk[crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES..crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES]);
    
    crate::indcpa::indcpa_enc((&mut ct_prime[0..crate::indcpa::KYBER_INDCPA_BYTES]).try_into().unwrap(), &m_prime, &pk, &r_prime);
    
    let mut fail: u8 = 0;
    for i in 0..crate::indcpa::KYBER_INDCPA_BYTES {
        fail |= ct[i] ^ ct_prime[i];
    }
    
    let mut z = [0u8; 32];
    z.copy_from_slice(&sk.sk[crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES + 32..crate::indcpa::KYBER_INDCPA_SECRETKEYBYTES + crate::indcpa::KYBER_INDCPA_PUBLICKEYBYTES + 64]);
    
    let fail_mask = fail.wrapping_sub(1); // 0xff if fail == 0 (match), 0x00 otherwise
    
    let mut k_final = [0u8; 32];
    for i in 0..32 {
        k_final[i] = (k_prime[i] & fail_mask) | (z[i] & !fail_mask);
    }
    
    let mut hasher_kdf = Sha3_256::new();
    hasher_kdf.update(&k_final);
    let mut hasher_ct = Sha3_256::new();
    hasher_ct.update(&ct);
    hasher_kdf.update(&hasher_ct.finalize());
    let ss = hasher_kdf.finalize();
    
    secret.key.copy_from_slice(&ss);
    
    secret
}
