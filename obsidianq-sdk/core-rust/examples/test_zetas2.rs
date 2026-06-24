use obsidian_core::ntt::{ZETAS};
use obsidian_core::reduce::montgomery_reduce;

fn main() {
    let q = 3329i32;
    for k in 1..10 {
        let z = ZETAS[k] as i32;
        let neg_z = -z;
        // Compute inverse of z using Fermat's Little Theorem: z^(q-2)
        // Note: z is in Montgomery domain, so we actually want the inverse in Montgomery domain?
        // Wait, ZETAS are in Montgomery domain! So Z = z * R mod Q.
        // What does Kyber use for zetas_inv?
        // Let's print out what Kyber's zetas_inv would be.
    }
    println!("Done");
}
