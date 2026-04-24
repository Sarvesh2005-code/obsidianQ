use rand_core::{RngCore, CryptoRng, Error};
use obsidian_core::kem::{generate_keypair, encapsulate_key, decapsulate_key};

/// A completely deterministic Mock RNG engineered strictly for injecting
/// known seeds to mathematically verify output tensors.
pub struct NISTMockRng {
    pub seed_buffer: Vec<u8>,
    pub position: usize,
}

impl NISTMockRng {
    pub fn new(seed: &[u8]) -> Self {
        NISTMockRng {
            seed_buffer: seed.to_vec(),
            position: 0,
        }
    }
}

impl RngCore for NISTMockRng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let len = dest.len();
        if self.position + len > self.seed_buffer.len() {
            // Loop the seed if exhausted (just for deterministic testing)
            for i in 0..len {
                dest[i] = self.seed_buffer[(self.position + i) % self.seed_buffer.len()];
            }
            self.position += len;
            return;
        }
        dest.copy_from_slice(&self.seed_buffer[self.position..self.position + len]);
        self.position += len;
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for NISTMockRng {}

#[test]
fn test_roundtrip_deterministic() {
    let seed = [0x42; 128]; // Arbitrary fixed seed for deterministic behavior
    let mut rng = NISTMockRng::new(&seed);

    // Key generation
    let (pk, sk) = generate_keypair(&mut rng);

    // Encapsulation
    let (ct, ss_enc) = encapsulate_key(&pk, &mut rng);

    // Decapsulation
    let ss_dec = decapsulate_key(&ct, &sk);

    // Shared secrets must match
    assert_eq!(ss_enc.key, ss_dec.key, "Encapsulated and decapsulated secrets must match");
}

#[test]
fn test_roundtrip_random() {
    use rand_core::OsRng;
    let mut rng = OsRng;

    for _ in 0..10 {
        let (pk, sk) = generate_keypair(&mut rng);
        let (ct, ss_enc) = encapsulate_key(&pk, &mut rng);
        let ss_dec = decapsulate_key(&ct, &sk);
        
        assert_eq!(ss_enc.key, ss_dec.key, "Shared secrets must match with random seeds");
    }
}
