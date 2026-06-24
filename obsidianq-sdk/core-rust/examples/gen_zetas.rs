use obsidian_core::ntt::ZETAS;

fn main() {
    let q = 3329i32;
    let r = 1044i32;
    let r_inv = 1698i32; // R^-1 mod 3329
    
    // We want to find the Montgomery-domain inverses of ZETAS.
    // Let's iterate and find them by brute force.
    println!("pub const ZETAS_INV: [i16; 128] = [");
    for k in 0..128 {
        let z = ZETAS[k] as i32; // z = z_true * R mod Q
        // We need z_inv such that montgomery_reduce(z * z_inv) == R mod Q
        // wait, montgomery_reduce(a * b) = a * b * R^-1 mod Q.
        // We want (z * z_inv) * R^-1 == R mod Q.
        // So z * z_inv == R^2 mod Q.
        let mut found = 0;
        for i in 0..3329 {
            let p = (z * i) % q;
            let mut p = p;
            if p < 0 { p += q; }
            let r2 = (r * r) % q;
            if p == r2 {
                found = i;
                break;
            }
        }
        let found_i16 = if found > 1664 { found - q } else { found } as i16;
        print!("{:5}, ", found_i16);
        if k % 16 == 15 { println!(); }
    }
    println!("];");
}
