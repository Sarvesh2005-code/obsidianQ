//! Bit-packing and serialization for polynomials and vectors.

use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::kem::{KYBER_K, KYBER_N};

pub const KYBER_POLYBYTES: usize = 384;
pub const KYBER_POLYVECBYTES: usize = KYBER_K * 320;
pub const KYBER_POLYCOMPRESSEDBYTES: usize = 128; // For K=3 (ML-KEM-768), du=10, dv=4
pub const KYBER_POLYVECCOMPRESSEDBYTES: usize = KYBER_K * 320;

/// Serialize polynomial to 384 bytes
pub fn poly_tobytes(r: &mut [u8; KYBER_POLYBYTES], a: &Poly) {
    for i in 0..(KYBER_N / 2) {
        let t0 = a.coeffs[2 * i] as u16;
        let t1 = a.coeffs[2 * i + 1] as u16;
        r[3 * i] = (t0 & 0xff) as u8;
        r[3 * i + 1] = ((t0 >> 8) | ((t1 & 0x0f) << 4)) as u8;
        r[3 * i + 2] = (t1 >> 4) as u8;
    }
}

/// Deserialize 384 bytes to polynomial
pub fn poly_frombytes(r: &mut Poly, a: &[u8; KYBER_POLYBYTES]) {
    for i in 0..(KYBER_N / 2) {
        r.coeffs[2 * i] = ((a[3 * i] as u16) | (((a[3 * i + 1] as u16) & 0x0f) << 8)) as i16;
        r.coeffs[2 * i + 1] = (((a[3 * i + 1] as u16) >> 4) | ((a[3 * i + 2] as u16) << 4)) as i16;
    }
}

/// Serialize polyvec to KYBER_POLYVECBYTES bytes
pub fn polyvec_tobytes(r: &mut [u8; KYBER_POLYVECBYTES], a: &PolyVec) {
    for i in 0..KYBER_K {
        let mut tmp = [0u8; 320];
        poly_compress_10(&mut tmp, &a.vec[i]);
        r[i * 320..(i + 1) * 320].copy_from_slice(&tmp);
    }
}

/// Deserialize KYBER_POLYVECBYTES bytes to polyvec
pub fn polyvec_frombytes(r: &mut PolyVec, a: &[u8; KYBER_POLYVECBYTES]) {
    for i in 0..KYBER_K {
        let mut tmp = [0u8; 320];
        tmp.copy_from_slice(&a[i * 320..(i + 1) * 320]);
        poly_decompress_10(&mut r.vec[i], &tmp);
    }
}

fn poly_compress_10(r: &mut [u8; 320], a: &Poly) {
    let mut t = [0u16; 4];
    for i in 0..(KYBER_N / 4) {
        for j in 0..4 {
            let mut u = a.coeffs[4 * i + j] as i32;
            u += (u >> 15) & crate::reduce::KYBER_Q as i32;
            t[j] = ((((u << 10) + crate::reduce::KYBER_Q as i32 / 2) / crate::reduce::KYBER_Q as i32) & 0x3ff) as u16;
        }
        r[5 * i] = (t[0] & 0xff) as u8;
        r[5 * i + 1] = ((t[0] >> 8) | ((t[1] & 0x3f) << 2)) as u8;
        r[5 * i + 2] = ((t[1] >> 6) | ((t[2] & 0x0f) << 4)) as u8;
        r[5 * i + 3] = ((t[2] >> 4) | ((t[3] & 0x03) << 6)) as u8;
        r[5 * i + 4] = (t[3] >> 2) as u8;
    }
}

fn poly_decompress_10(r: &mut Poly, a: &[u8; 320]) {
    for i in 0..(KYBER_N / 4) {
        let t0 = (a[5 * i] as u16) | (((a[5 * i + 1] as u16) & 0x03) << 8);
        let t1 = ((a[5 * i + 1] as u16) >> 2) | (((a[5 * i + 2] as u16) & 0x0f) << 6);
        let t2 = ((a[5 * i + 2] as u16) >> 4) | (((a[5 * i + 3] as u16) & 0x3f) << 4);
        let t3 = ((a[5 * i + 3] as u16) >> 6) | ((a[5 * i + 4] as u16) << 2);

        r.coeffs[4 * i] = (((t0 as u32 * crate::reduce::KYBER_Q as u32) + 512) >> 10) as i16;
        r.coeffs[4 * i + 1] = (((t1 as u32 * crate::reduce::KYBER_Q as u32) + 512) >> 10) as i16;
        r.coeffs[4 * i + 2] = (((t2 as u32 * crate::reduce::KYBER_Q as u32) + 512) >> 10) as i16;
        r.coeffs[4 * i + 3] = (((t3 as u32 * crate::reduce::KYBER_Q as u32) + 512) >> 10) as i16;
    }
}

pub fn poly_compress_4(r: &mut [u8; 128], a: &Poly) {
    let mut t = [0u8; 8];
    for i in 0..(KYBER_N / 8) {
        for j in 0..8 {
            let mut u = a.coeffs[8 * i + j] as i32;
            u += (u >> 15) & crate::reduce::KYBER_Q as i32;
            t[j] = ((((u << 4) + crate::reduce::KYBER_Q as i32 / 2) / crate::reduce::KYBER_Q as i32) & 0x0f) as u8;
        }
        r[i * 4] = t[0] | (t[1] << 4);
        r[i * 4 + 1] = t[2] | (t[3] << 4);
        r[i * 4 + 2] = t[4] | (t[5] << 4);
        r[i * 4 + 3] = t[6] | (t[7] << 4);
    }
}

pub fn poly_decompress_4(r: &mut Poly, a: &[u8; 128]) {
    for i in 0..(KYBER_N / 2) {
        r.coeffs[2 * i] = (((a[i] & 0x0f) as u32 * crate::reduce::KYBER_Q as u32 + 8) >> 4) as i16;
        r.coeffs[2 * i + 1] = (((a[i] >> 4) as u32 * crate::reduce::KYBER_Q as u32 + 8) >> 4) as i16;
    }
}
