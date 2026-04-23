use obsidian_core::indcpa::*;
use obsidian_core::poly::*;
use obsidian_core::polyvec::*;

fn main() {
    let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
    let mut sk = [0u8; KYBER_INDCPA_SECRETKEYBYTES];
    let seed = [1u8; 32];
    let noiseseed = [2u8; 32];
    indcpa_keypair(&mut pk, &mut sk, &seed, &noiseseed);
    
    let mut ct = [0u8; KYBER_INDCPA_BYTES];
    let m = [3u8; 32];
    let coins = [4u8; 32];
    indcpa_enc(&mut ct, &m, &pk, &coins);
    
    let mut m_dec = [0u8; 32];
    indcpa_dec(&mut m_dec, &ct, &sk);
    
    if m == m_dec {
        println!("IND-CPA works!");
    } else {
        println!("IND-CPA failed!");
    }
}
