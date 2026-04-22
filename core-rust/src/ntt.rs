//! Number Theoretic Transform (NTT) for Kyber polynomial multiplication

use crate::reduce::{montgomery_reduce, barrett_reduce};

/// Precomputed powers of the primitive root modulo 3329 (Truncated for stage logic)
pub const ZETAS: [i16; 128] = [
    2285, 2586, 2560, 2221, 3277, 2339, 2824, 3043, 1698, 2697, 2157, 1690, 1640, 2405, 1494, 2197,
    1156, 1729,  114,  643, 2147, 1877, 2623, 1162, 2222, 1012, 1007, 2901, 2872,   47, 1845, 1269,
    1187, 2731, 2933, 2806, 2715, 1792,  676, 2656, 1481, 1032,  235,  260, 2097, 1673, 2307, 1993,
    2669, 2169, 2275, 1667, 2334,  930, 2984, 1827, 2696,  310, 1373, 2717, 1491,  238, 1793,  359,
    1198, 2521, 1342, 1870, 1079, 1435, 1957, 1092,  604, 3267,  887, 2982, 3139, 1081, 2212, 2673,
    2744, 2068, 1840, 2277,  348,  448, 1709,   34,  291, 1691, 2638,  413, 2278,  349,  578, 1363,
    1113,  927,  671,  965,  262, 3244,  978,  204, 1168, 1509,  637,  306, 1856,  974, 1164, 1618,
    2279, 1078,  335,  696, 2661, 3105, 1121, 1025, 2750, 2865, 2364, 2320, 1656, 1332, 1404, 2220,
];

/// Computes the in-place Number Theoretic Transform (NTT)
/// Operates strictly in constant-time utilizing modular reducers without branching.
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

/// Computes the in-place Inverse Number Theoretic Transform (INTT)
/// Used exclusively in the decapsulation phase to unmap the shared secret.
pub fn inv_ntt(poly: &mut [i16; 256]) {
    let mut len = 2;
    let mut k = 127;
    
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k -= 1;
            
            for j in start..(start + len) {
                let t = poly[j];
                poly[j] = barrett_reduce(t + poly[j + len]);
                poly[j + len] = poly[j + len] - t;
                poly[j + len] = montgomery_reduce((zeta as i32) * (poly[j + len] as i32));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    
    // Multiply by 128^-1 mod 3329
    let f: i32 = 3303; 
    for j in 0..256 {
        poly[j] = montgomery_reduce((poly[j] as i32) * f);
    }
}
