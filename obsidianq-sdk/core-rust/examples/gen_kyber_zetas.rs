use std::fmt::Write;

const Q: i32 = 3329;
const MONT: i32 = 1044; // R mod Q
const QINV: i32 = 62209;

fn main() {
    let mut zetas = [0i16; 128];
    let mut zetas_inv = [0i16; 128];
    
    // Base zeta = 17. In Montgomery domain: 17 * 1044 mod 3329 = 1087 ? wait.
    let zeta = 17i32; 
    let mut zeta_pow = 1i32; // zeta^0
    
    let mut powers = [0i32; 128];
    for i in 0..128 {
        powers[i] = zeta_pow;
        zeta_pow = (zeta_pow * zeta) % Q;
    }
    
    // bit reverse
    for i in 0..128 {
        let mut br = 0;
        for j in 0..7 {
            if (i & (1 << j)) != 0 {
                br |= 1 << (6 - j);
            }
        }
        
        let p = powers[br];
        // convert to montgomery domain
        zetas[i] = ((p * 1044) % Q) as i16;
        
        // compute inverse in montgomery domain
        // inv(p) = p^(Q-2)
        let mut p_inv = 1;
        for _ in 0..(Q-2) {
            p_inv = (p_inv * p) % Q;
        }
        zetas_inv[i] = ((p_inv * 1044) % Q) as i16;
    }
    
    println!("pub const ZETAS_INV_KYBER: [i16; 128] = {:?};", zetas_inv);
}
