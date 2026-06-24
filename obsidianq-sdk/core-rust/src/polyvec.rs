//! Polynomial vector math for ML-KEM

use crate::kem::KYBER_K;
use crate::poly::Poly;

#[derive(Clone)]
pub struct PolyVec {
    pub vec: [Poly; KYBER_K],
}

impl PolyVec {
    pub fn new() -> Self {
        Self {
            vec: [Poly::new(); KYBER_K],
        }
    }

    pub fn ntt(&mut self) {
        for i in 0..KYBER_K {
            self.vec[i].ntt();
        }
    }

    pub fn inv_ntt(&mut self) {
        for i in 0..KYBER_K {
            self.vec[i].inv_ntt();
        }
    }

    pub fn reduce(&mut self) {
        for i in 0..KYBER_K {
            self.vec[i].reduce();
        }
    }

    pub fn add(&mut self, a: &PolyVec, b: &PolyVec) {
        for i in 0..KYBER_K {
            self.vec[i].add(&a.vec[i], &b.vec[i]);
        }
    }

    /// Point-wise multiply and add polynomials
    pub fn basemul_acc_montgomery(r: &mut Poly, a: &PolyVec, b: &PolyVec) {
        let mut t = Poly::new();
        r.basemul_montgomery(&a.vec[0], &b.vec[0]);
        for i in 1..KYBER_K {
            t.basemul_montgomery(&a.vec[i], &b.vec[i]);
            r.add(&r.clone(), &t);
        }
        r.reduce();
    }
}
