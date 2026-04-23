use obsidian_core::ntt::ZETAS;

fn main() {
    let a = -1143i32;
    let b = 30i32;
    let m1 = obsidian_core::reduce::montgomery_reduce(a * b);
    let m2 = obsidian_core::reduce::montgomery_reduce((a + 3329) * b);
    println!("m1: {}, m2: {}", m1, m2);
}
