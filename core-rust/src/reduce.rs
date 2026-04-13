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

/// Barrett reduction reduces an integer loosely modulo q in constant-time.
#[inline(always)]
pub fn barrett_reduce(a: i16) -> i16 {
    // 2^26 / q
    let v = ((1i32 << 26) / (KYBER_Q as i32) + 1) as i16;
    let mut t = (a as i32).wrapping_mul(v as i32) >> 26;
    t = t.wrapping_mul(KYBER_Q as i32);
    a.wrapping_sub(t as i16)
}
