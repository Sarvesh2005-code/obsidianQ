//! Constant-time arithmetic reducers for Kyber modulus q = 3329
//! This module completely avoids branching (if/else) to prevent timing attacks.

// Kyber specifics from NIST FIPS 203
pub const KYBER_Q: i16 = 3329;
pub const KYBER_QINV: i32 = 62209; // q^-1 mod 2^16

/// Montgomery reduction in constant-time.
/// Safely maps large multiplied polynomials back down into the ring range.
#[inline(always)]
pub fn montgomery_reduce(a: i32) -> i16 {
    // Operations executed as strict bitwise math. Safe across all values.
    let t = (a.wrapping_mul(KYBER_QINV)) as i16;
    let t_q = (t as i32).wrapping_mul(KYBER_Q as i32);
    let res = (a.wrapping_sub(t_q)) >> 16;
    res as i16
}

/// Barrett reduction reduces a 16-bit integer to centered representative mod q.
/// Exact port of pq-crystals/kyber reference.
#[inline(always)]
pub fn barrett_reduce(a: i16) -> i16 {
    // v = ((1<<26) + Q/2) / Q = 20159
    let v: i16 = 20159;
    let mut t = ((v as i32) * (a as i32) + (1 << 25)) >> 26;
    t *= KYBER_Q as i32;
    a - (t as i16)
}
