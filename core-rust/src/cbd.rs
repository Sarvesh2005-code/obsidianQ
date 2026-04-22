//! Centered Binomial Distribution (CBD) for ML-KEM

use crate::kem::KYBER_N;

/// Load 24 bits from a byte array
fn load24_little_endian(x: &[u8]) -> u32 {
    (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16)
}

/// CBD2 sampling for ML-KEM-768
/// Takes a byte array of 64 bytes (2 bits * 256 = 512 bits)
/// and produces 256 polynomial coefficients.
pub fn cbd2(buf: &[u8; 64], r: &mut [i16; KYBER_N]) {
    for i in 0..KYBER_N / 4 {
        let t = load24_little_endian(&buf[3 * i..]);
        let mut d = t & 0x00249249;
        d = d.wrapping_add((t >> 1) & 0x00249249);
        d = d.wrapping_add((t >> 2) & 0x00249249);

        for j in 0..4 {
            let a = ((d >> (6 * j)) & 0x7) as i16;
            let b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r[4 * i + j] = a - b;
        }
    }
}
