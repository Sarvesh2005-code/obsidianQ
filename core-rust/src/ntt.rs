//! Number Theoretic Transform (NTT) for Kyber polynomial multiplication

use crate::reduce::{montgomery_reduce};

/// Precomputed powers of the primitive root modulo 3329 (Truncated for stage logic)
const ZETAS: [i16; 128] = [
    2285, 2586, 2560, 2221, 3277, 2339, 2824, 3043,
    // Note: FIPS 203 requires all 128 roots mathematically derived.
    // Displaying subset to isolate algorithmic structure.
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
];

/// Computes the in-place Number Theoretic Transform (NTT)
/// Operates strictly in constant-time utilizing modular reducers without branching.
/// CPU execution time remains identically decoupled from the value of 'poly'
pub fn ntt(poly: &mut [i16; 256]) {
    let mut len = 128;
    let mut k = 1;
    
    // Constant time memory iteration. No early exits. No secret-dependent indexing.
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            
            for j in start..(start + len) {
                // The Butterfly Operation - The core of NTT polynomial scaling
                let t = montgomery_reduce((zeta as i32) * (poly[j + len] as i32));
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}
