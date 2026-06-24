use obsidian_core::ntt::{ntt, inv_ntt};
use obsidian_core::reduce::{KYBER_Q, montgomery_reduce};

/// Check if two values are congruent mod Q
fn congruent_mod_q(a: i16, b: i16) -> bool {
    let q = KYBER_Q as i32;
    let mut diff = (a as i32 - b as i32) % q;
    if diff < 0 { diff += q; }
    diff == 0
}

fn main() {
    // The NTT -> INTT round-trip produces x * R^{-1} * R = x (if properly scaled)
    // Actually, invntt_tomont maps: NTT domain -> normal domain * mont factor
    // So NTT(x) -> invntt_tomont -> x * R (in montgomery domain)
    // Wait, let me re-read: invntt does fqmul(r[j], 1441) at the end
    // where 1441 = R^2 / 128 mod Q
    // So the full round trip: NTT -> INTT gives x * (1/128) * R^2 * R^{-1} = x * R / 128
    // Hmm, this is getting confusing. Let me just check mod Q congruence.
    
    println!("=== Simple Round-trip Test ===");
    let mut original = [0i16; 256];
    original[0] = 1;
    original[1] = 2;
    original[2] = 3;
    original[3] = 4;
    
    let mut poly = original.clone();
    ntt(&mut poly);
    inv_ntt(&mut poly);
    
    println!("Original: {:?}", &original[0..8]);
    println!("After NTT->INTT: {:?}", &poly[0..8]);
    
    // Check if results are congruent mod Q
    let mut all_congruent = true;
    for i in 0..256 {
        if !congruent_mod_q(poly[i], original[i]) {
            println!("NOT CONGRUENT at [{}]: orig={}, got={}", i, original[i], poly[i]);
            all_congruent = false;
        }
    }
    println!("All congruent mod Q: {}", all_congruent);
    
    // Test what the actual scaling factor is
    // If original[0] = 1 and result[0] = R, then scale = R
    println!("\nScaling analysis:");
    println!("  Input[0] = 1, Output[0] = {}", poly[0]);
    println!("  Input[1] = 2, Output[1] = {} (expected 2x scale = {})", poly[1], poly[0] as i32 * 2);
    
    // Check: is poly[0] ≡ R mod Q where R = 2^16?
    let r_mod_q = (1i64 << 16) % (KYBER_Q as i64);
    println!("  R mod Q = {}", r_mod_q);
    println!("  R^(-1) mod Q: compute via fermat...");
    
    // R^-1 mod Q
    let mut r_inv = 1i64;
    for _ in 0..3327 {
        r_inv = (r_inv * r_mod_q) % KYBER_Q as i64;
    }
    println!("  R^(-1) mod Q = {}", r_inv);
    
    // What's the scaling? output[0] / input[0] mod Q should tell us
    let scale = poly[0] as i32;
    println!("  Scale factor (output/input for coeff 0) = {}", scale);
    
    // Is it 1? (identity)
    // Is it R? (one extra Montgomery factor)
    // Is it R^{-1}? (one inverse Montgomery factor)
    
    // Let's verify: does NTT(INTT(x)) = x for NTT-domain input?
    println!("\n=== Reverse test: INTT then NTT ===");
    let mut poly2 = [0i16; 256];
    poly2[0] = 100;
    poly2[1] = 200;
    let orig2 = poly2.clone();
    inv_ntt(&mut poly2);
    ntt(&mut poly2);
    println!("Original NTT-domain: {:?}", &orig2[0..4]);
    println!("After INTT->NTT: {:?}", &poly2[0..4]);
    
    // Final: check if NTT->INTT produces exact original when input is already "Montgomery-prepared"
    println!("\n=== Montgomery-domain input test ===");
    // If we multiply input by R before NTT, does INTT give us back input*R?
    let mut poly3 = [0i16; 256];
    // Put 1 in "Montgomery domain": 1 * R mod Q = R mod Q
    poly3[0] = r_mod_q as i16;  // R mod Q = should be some value
    let orig3_0 = poly3[0];
    ntt(&mut poly3);
    inv_ntt(&mut poly3);
    println!("Input (1*R): {}, After NTT->INTT: {}", orig3_0, poly3[0]);
    println!("Is result congruent to input mod Q? {}", congruent_mod_q(poly3[0], orig3_0));
}
