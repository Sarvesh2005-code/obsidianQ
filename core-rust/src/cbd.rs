//! Centered Binomial Distribution (CBD) for ML-KEM
//! FIPS 203 Section 4.3 - SamplePolyCBD_η

use crate::kem::KYBER_N;

/// Load 32 bits from a byte array (little-endian)
fn load32_little_endian(x: &[u8]) -> u32 {
    (x[0] as u32)
        | ((x[1] as u32) << 8)
        | ((x[2] as u32) << 16)
        | ((x[3] as u32) << 24)
}

/// CBD2 sampling for ML-KEM-768 (η = 2)
/// 
/// Takes a byte array of 128 bytes (η * KYBER_N / 4 = 2 * 256 / 4 = 128)
/// and produces 256 polynomial coefficients in [-2, 2].
/// 
/// Each coefficient is computed as: a - b where
/// a = popcount(2 random bits), b = popcount(2 random bits)
pub fn cbd2(buf: &[u8], r: &mut [i16; KYBER_N]) {
    // For η=2: we need 4 bits per coefficient (2 bits for a, 2 bits for b)
    // Total: 256 * 4 = 1024 bits = 128 bytes
    // We process 32 bits at a time → 8 coefficients per iteration
    for i in 0..KYBER_N / 8 {
        let t = load32_little_endian(&buf[4 * i..]);
        // Extract the sum of bit pairs for 'a' and 'b' halves
        let d = t & 0x55555555;
        let d = d.wrapping_add((t >> 1) & 0x55555555);
        
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r[8 * i + j] = a - b;
        }
    }
}
