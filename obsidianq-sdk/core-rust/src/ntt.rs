//! Number Theoretic Transform (NTT) for Kyber polynomial multiplication
//! Exact port of pq-crystals/kyber reference implementation (ntt.c)

use crate::reduce::{montgomery_reduce, barrett_reduce};

/// Precomputed zeta constants in Montgomery domain.
/// Exact values from pq-crystals/kyber reference (signed, centered).
pub const ZETAS: [i16; 128] = [
  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
  -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
   -108,  -308,   996,   991,   958, -1460,  1522,  1628,
];

/// Computes the in-place Number Theoretic Transform (NTT).
/// Input in standard order, output in bit-reversed order.
/// Operates in constant-time — no branching on secret data.
pub fn ntt(poly: &mut [i16; 256]) {
    let mut len = 128;
    let mut k: usize = 1;
    
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            
            for j in start..(start + len) {
                let t = montgomery_reduce((zeta as i32) * (poly[j + len] as i32));
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Computes the in-place Inverse NTT and multiplies by Montgomery factor 2^16.
/// Input in bit-reversed order, output in standard order.
pub fn inv_ntt(poly: &mut [i16; 256]) {
    let mut len = 2;
    let mut k: usize = 127;
    
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k = k.wrapping_sub(1);
            
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
    
    // Final scaling: multiply by mont^2/128 = 1441
    let f: i32 = 1441;
    for j in 0..256 {
        poly[j] = montgomery_reduce((poly[j] as i32) * f);
    }
}
