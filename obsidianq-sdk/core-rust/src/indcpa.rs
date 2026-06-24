//! CPA-secure public key encryption scheme underlying ML-KEM

use crate::kem::{KYBER_K, KYBER_N};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::symmetric::{prf, xof_state, XofReader};
use crate::pack::{polyvec_tobytes, polyvec_frombytes, KYBER_POLYVECBYTES, KYBER_POLYVECCOMPRESSEDBYTES};
use crate::cbd::cbd2;

pub const KYBER_INDCPA_PUBLICKEYBYTES: usize = KYBER_POLYVECBYTES + 32;
pub const KYBER_INDCPA_SECRETKEYBYTES: usize = KYBER_POLYVECBYTES;
pub const KYBER_INDCPA_BYTES: usize = KYBER_POLYVECCOMPRESSEDBYTES + 128; // 1088

/// Generate matrix A from seed via rejection sampling.
fn gen_matrix(a: &mut [PolyVec; KYBER_K], seed: &[u8; 32], transposed: bool) {
    for i in 0..KYBER_K {
        for j in 0..KYBER_K {
            let (x, y) = if transposed { (i as u8, j as u8) } else { (j as u8, i as u8) };
            let mut xof = xof_state(seed, x, y);
            
            let mut ctr = 0;
            let mut buf = [0u8; 3];
            while ctr < KYBER_N {
                xof.read(&mut buf);
                
                let d1 = buf[0] as u16 | ((buf[1] as u16 & 0x0f) << 8);
                let d2 = (buf[1] as u16 >> 4) | ((buf[2] as u16 & 0xff) << 4);

                if d1 < crate::reduce::KYBER_Q as u16 {
                    a[i].vec[j].coeffs[ctr] = d1 as i16;
                    ctr += 1;
                }
                if ctr < KYBER_N && d2 < crate::reduce::KYBER_Q as u16 {
                    a[i].vec[j].coeffs[ctr] = d2 as i16;
                    ctr += 1;
                }
            }
        }
    }
}

pub fn indcpa_keypair(pk: &mut [u8; KYBER_INDCPA_PUBLICKEYBYTES], sk: &mut [u8; KYBER_INDCPA_SECRETKEYBYTES], seed: &[u8; 32], noiseseed: &[u8; 32]) {
    let mut a = [PolyVec::new(), PolyVec::new(), PolyVec::new()];
    let mut e = PolyVec::new();
    let mut pkpv = PolyVec::new();
    let mut skpv = PolyVec::new();
    
    // Generate matrix A
    gen_matrix(&mut a, seed, false);
    
    // Sample secret vector s (η=2 requires 128 bytes per polynomial)
    for i in 0..KYBER_K {
        let prf_out = prf(noiseseed, i as u8, 128);
        cbd2(&prf_out, &mut skpv.vec[i].coeffs);
    }
    skpv.ntt();
    
    // Sample error vector e
    for i in 0..KYBER_K {
        let prf_out = prf(noiseseed, (i + KYBER_K) as u8, 128);
        cbd2(&prf_out, &mut e.vec[i].coeffs);
    }
    e.ntt();
    
    // pk = A * s + e (all in NTT domain)
    for i in 0..KYBER_K {
        PolyVec::basemul_acc_montgomery(&mut pkpv.vec[i], &a[i], &skpv);
        pkpv.vec[i].tomont();
        pkpv.vec[i].add(&pkpv.vec[i].clone(), &e.vec[i]);
        pkpv.vec[i].reduce();
    }
    
    // Pack sk
    let mut sk_bytes = [0u8; KYBER_POLYVECBYTES];
    polyvec_tobytes(&mut sk_bytes, &skpv);
    sk.copy_from_slice(&sk_bytes);
    
    // Pack pk = (pkpv || seed)
    let mut pk_bytes = [0u8; KYBER_POLYVECBYTES];
    polyvec_tobytes(&mut pk_bytes, &pkpv);
    pk[0..KYBER_POLYVECBYTES].copy_from_slice(&pk_bytes);
    pk[KYBER_POLYVECBYTES..].copy_from_slice(seed);
}

pub fn indcpa_enc(c: &mut [u8; KYBER_INDCPA_BYTES], m: &[u8; 32], pk: &[u8; KYBER_INDCPA_PUBLICKEYBYTES], coins: &[u8; 32]) {
    let mut a = [PolyVec::new(), PolyVec::new(), PolyVec::new()];
    let mut sp = PolyVec::new();
    let mut ep = PolyVec::new();
    let mut epp = Poly::new();
    let mut pkpv = PolyVec::new();
    let mut k = Poly::new();
    let mut b = PolyVec::new();
    let mut v = Poly::new();
    
    let mut pk_bytes = [0u8; KYBER_POLYVECBYTES];
    pk_bytes.copy_from_slice(&pk[0..KYBER_POLYVECBYTES]);
    polyvec_frombytes(&mut pkpv, &pk_bytes);
    
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&pk[KYBER_POLYVECBYTES..]);
    
    gen_matrix(&mut a, &seed, true);
    
    // Sample vectors sp, ep, epp
    for i in 0..KYBER_K {
        let prf_out = prf(coins, i as u8, 128);
        cbd2(&prf_out, &mut sp.vec[i].coeffs);
    }
    
    for i in 0..KYBER_K {
        let prf_out = prf(coins, (i + KYBER_K) as u8, 128);
        cbd2(&prf_out, &mut ep.vec[i].coeffs);
    }
    
    let prf_out = prf(coins, (KYBER_K * 2) as u8, 128);
    cbd2(&prf_out, &mut epp.coeffs);
    
    sp.ntt();
    
    // b = A^T * sp + ep
    for i in 0..KYBER_K {
        PolyVec::basemul_acc_montgomery(&mut b.vec[i], &a[i], &sp);
        b.vec[i].inv_ntt();
        b.vec[i].add(&b.vec[i].clone(), &ep.vec[i]);
        b.vec[i].reduce();
    }
    
    // v = pk^T * sp + epp + encode(m)
    PolyVec::basemul_acc_montgomery(&mut v, &pkpv, &sp);
    v.inv_ntt();
    v.add(&v.clone(), &epp);
    
    k.from_msg(m);
    v.add(&v.clone(), &k);
    v.reduce();
    
    // Compress and pack ciphertext
    let mut b_bytes = [0u8; crate::pack::KYBER_POLYVECCOMPRESSEDBYTES];
    crate::pack::polyvec_compress_10(&mut b_bytes, &b);
    c[0..crate::pack::KYBER_POLYVECCOMPRESSEDBYTES].copy_from_slice(&b_bytes);
    
    let mut v_bytes = [0u8; 128];
    crate::pack::poly_compress_4(&mut v_bytes, &v);
    c[crate::pack::KYBER_POLYVECCOMPRESSEDBYTES..crate::pack::KYBER_POLYVECCOMPRESSEDBYTES + 128].copy_from_slice(&v_bytes);
}

pub fn indcpa_dec(m: &mut [u8; 32], c: &[u8; KYBER_INDCPA_BYTES], sk: &[u8; KYBER_INDCPA_SECRETKEYBYTES]) {
    let mut b = PolyVec::new();
    let mut skpv = PolyVec::new();
    let mut v = Poly::new();
    let mut mp = Poly::new();
    
    // Decompress b from ciphertext
    let mut b_bytes = [0u8; crate::pack::KYBER_POLYVECCOMPRESSEDBYTES];
    b_bytes.copy_from_slice(&c[0..crate::pack::KYBER_POLYVECCOMPRESSEDBYTES]);
    crate::pack::polyvec_decompress_10(&mut b, &b_bytes);
    
    // Deserialize secret key
    let mut sk_bytes = [0u8; KYBER_POLYVECBYTES];
    sk_bytes.copy_from_slice(&sk[0..KYBER_POLYVECBYTES]);
    polyvec_frombytes(&mut skpv, &sk_bytes);
    
    // Decompress v from ciphertext
    let mut v_bytes = [0u8; 128];
    v_bytes.copy_from_slice(&c[crate::pack::KYBER_POLYVECCOMPRESSEDBYTES..crate::pack::KYBER_POLYVECCOMPRESSEDBYTES + 128]);
    crate::pack::poly_decompress_4(&mut v, &v_bytes);
    
    // mp = b^T * s (in NTT domain, then INTT)
    b.ntt();
    PolyVec::basemul_acc_montgomery(&mut mp, &b, &skpv);
    mp.inv_ntt();
    
    // m' = v - mp
    v.sub(&v.clone(), &mp);
    v.reduce();
    
    let msg = v.to_msg();
    m.copy_from_slice(&msg);
}
