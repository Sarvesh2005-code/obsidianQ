//! Polynomial math for ML-KEM

use crate::kem::KYBER_N;
use crate::reduce::{montgomery_reduce, barrett_reduce, KYBER_Q};
use crate::ntt::{ntt, inv_ntt};

#[derive(Clone, Copy)]
pub struct Poly {
    pub coeffs: [i16; KYBER_N],
}

impl Poly {
    pub fn new() -> Self {
        Self {
            coeffs: [0; KYBER_N],
        }
    }

    pub fn add(&mut self, a: &Poly, b: &Poly) {
        for i in 0..KYBER_N {
            self.coeffs[i] = a.coeffs[i] + b.coeffs[i];
        }
    }

    pub fn sub(&mut self, a: &Poly, b: &Poly) {
        for i in 0..KYBER_N {
            self.coeffs[i] = a.coeffs[i] - b.coeffs[i];
        }
    }

    pub fn reduce(&mut self) {
        for i in 0..KYBER_N {
            self.coeffs[i] = barrett_reduce(self.coeffs[i]);
        }
    }

    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    pub fn inv_ntt(&mut self) {
        inv_ntt(&mut self.coeffs);
    }

    pub fn basemul_montgomery(&mut self, a: &Poly, b: &Poly) {
        for i in 0..(KYBER_N / 4) {
            let zeta0 = crate::ntt::ZETAS[64 + i];
            let (r0, r1) = basemul(&a.coeffs[4 * i..4 * i + 2], &b.coeffs[4 * i..4 * i + 2], zeta0);
            self.coeffs[4 * i] = r0;
            self.coeffs[4 * i + 1] = r1;
            let (r2, r3) = basemul(&a.coeffs[4 * i + 2..4 * i + 4], &b.coeffs[4 * i + 2..4 * i + 4], -zeta0);
            self.coeffs[4 * i + 2] = r2;
            self.coeffs[4 * i + 3] = r3;
        }
    }

    pub fn to_msg(&self) -> [u8; 32] {
        let mut msg = [0u8; 32];
        for i in 0..32 {
            let mut val = 0;
            for j in 0..8 {
                let mut u = self.coeffs[8 * i + j];
                u += (u >> 15) & crate::reduce::KYBER_Q;
                let mut t = (u as i32 * 2 + crate::reduce::KYBER_Q as i32 / 2) / crate::reduce::KYBER_Q as i32;
                t &= 1;
                val |= t << j;
            }
            msg[i] = val as u8;
        }
        msg
    }

    pub fn from_msg(&mut self, msg: &[u8; 32]) {
        for i in 0..32 {
            for j in 0..8 {
                let mask = -(((msg[i] >> j) & 1) as i16);
                self.coeffs[8 * i + j] = mask & ((KYBER_Q as i16 + 1) / 2);
            }
        }
    }
}

fn basemul(a: &[i16], b: &[i16], zeta: i16) -> (i16, i16) {
    let r0 = montgomery_reduce(a[1] as i32 * b[1] as i32);
    let r0 = montgomery_reduce(r0 as i32 * zeta as i32);
    let r0 = r0 + montgomery_reduce(a[0] as i32 * b[0] as i32);
    
    let r1 = montgomery_reduce(a[0] as i32 * b[1] as i32);
    let r1 = r1 + montgomery_reduce(a[1] as i32 * b[0] as i32);
    
    (r0, r1)
}

impl Poly {
    /// In-place conversion to Montgomery domain.
    pub fn tomont(&mut self) {
        let f = 1353; // 2^32 % 3329 = R^2 % Q
        for i in 0..256 {
            self.coeffs[i] = montgomery_reduce((self.coeffs[i] as i32) * f);
        }
    }
}
