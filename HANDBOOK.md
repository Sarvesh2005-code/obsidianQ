# ObsidianQ — Technical Handbook

> Complete reference guide for understanding the project's vision, architecture, security model, and production deployment.

---

## 1. Project Vision

As quantum computing advances, classical cryptographic algorithms (RSA, ECC) are increasingly vulnerable to **Shor's Algorithm**. Nation-state actors are already executing **"Store Now, Decrypt Later" (SNDL)** campaigns — harvesting encrypted data today to decrypt when quantum computers mature.

**ObsidianQ** provides enterprise Java applications with an immediate, drop-in replacement for their key encapsulation mechanisms. By writing the core mathematics in **Rust** and bridging to **Java** via zero-copy JNI, ObsidianQ prevents sensitive key material from lingering in the JVM's unpredictable Garbage Collection cycles.

### Target Applications
- **Fintech & Banking:** Protect financial transactions and HSM integrations against future quantum decryption.
- **Secure Messaging:** End-to-end encrypted chat systems requiring forward secrecy with post-quantum key exchange.
- **IoT & Edge Computing:** Lightweight KEM operations for resource-constrained devices in the Java ecosystem.
- **Government & Defense:** FIPS 203 compliance for classified data protection.

---

## 2. Technical Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Core Math** | Rust (stable) | NTT, Montgomery/Barrett reductions, SHAKE/SHA3, constant-time arithmetic |
| **FFI Bridge** | JNI via `DirectByteBuffer` | Zero-copy memory boundary between JVM and native code |
| **Java API** | JCA Provider + `javax.crypto.KEM` (Java 21) | Drop-in integration with standard Java security infrastructure |
| **Memory Safety** | `zeroize` crate | Deterministic secret key material cleanup on drop |
| **Build System** | Maven + Cargo | Maven triggers Cargo builds automatically during `generate-resources` |

---

## 3. FIPS 203 (ML-KEM-768) Implementation Details

### Parameter Set
| Parameter | Value | Description |
|---|---|---|
| `n` | 256 | Polynomial degree |
| `k` | 3 | Module rank (ML-KEM-768) |
| `q` | 3329 | Prime modulus |
| `η₁, η₂` | 2 | CBD noise parameter |
| Public Key Size | 1184 bytes | Serialized polynomial vector + seed |
| Secret Key Size | 2400 bytes | sk ∥ pk ∥ H(pk) ∥ z |
| Ciphertext Size | 1088 bytes | Compressed polynomial vector + compressed v |
| Shared Secret | 32 bytes | AES-256 compatible key material |

### Cryptographic Flow
```
KeyGen:
  d, z ← Random(32)
  (ρ, σ) = SHA3-512(d)
  A = Gen_Matrix(ρ)          // SHAKE-128 rejection sampling
  s = CBD₂(σ, 0..k-1)        // Secret vector
  e = CBD₂(σ, k..2k-1)       // Error vector
  NTT(s), NTT(e)
  t = A·s + e                 // Public key polynomial
  pk = (t, ρ)
  sk = (s ∥ pk ∥ H(pk) ∥ z)

Encapsulate(pk):
  m ← Random(32)
  m = SHA3-256(m)              // Regularize
  (K, r) = SHA3-512(m ∥ H(pk))
  ct = IND-CPA-Enc(pk, m, r)
  ss = KDF(K ∥ H(ct))         // Shared secret

Decapsulate(ct, sk):
  m' = IND-CPA-Dec(ct, sk)
  (K', r') = SHA3-512(m' ∥ H(pk))
  ct' = IND-CPA-Enc(pk, m', r')
  if ct == ct':                // Re-encryption check
    ss = KDF(K' ∥ H(ct))
  else:
    ss = KDF(z ∥ H(ct))       // Implicit rejection
```

---

## 4. The Memory Model (Zero-Copy Architecture)

### Why Off-Heap?
In standard Java applications, cryptographic keys stored on the JVM heap face these threats:
1. **GC Copies:** The garbage collector moves objects, leaving uncontrolled copies of private keys in freed heap regions.
2. **Heap Dumps:** JVM heap dumps (`.hprof`) contain all heap-resident data, including keys.
3. **Memory Scraping:** Attackers with memory access can scan the heap for key patterns.

### How ObsidianQ Prevents This
```
┌──────────────────────────────────────────────┐
│                JVM Heap                       │
│  ┌──────────────────────────┐                │
│  │ DirectByteBuffer (handle) │───────┐       │
│  │ (No key data on heap!)   │       │       │
│  └──────────────────────────┘       │       │
└─────────────────────────────────────┼───────┘
                                      │
          JNI FFI Boundary            │
                                      ▼
┌──────────────────────────────────────────────┐
│             Native (Rust) Memory              │
│  ┌──────────────────────────┐                │
│  │ Secret Key Bytes          │                │
│  │ [Zeroize on Drop]        │                │
│  │ [Constant-Time Math]     │                │
│  └──────────────────────────┘                │
└──────────────────────────────────────────────┘
```

1. Java allocates `ByteBuffer.allocateDirect()` for native memory blocks.
2. Raw memory addresses pass to Rust via JNI pointers.
3. Rust populates keys, performs all math, randomizes entropy.
4. Java retrieves only public parameters; secrets never cross the boundary.
5. When the Rust `KyberSecretKey` goes out of scope, `ZeroizeOnDrop` overwrites all bytes with zeroes.

---

## 5. Java 21 Integration (`javax.crypto.KEM`)

Java 21 introduced the `javax.crypto.KEM` API (JEP 452) specifically designed for Key Encapsulation Mechanisms. ObsidianQ implements `KEMSpi` to provide native support:

```java
// Standard Java 21 KEM API
Security.addProvider(new ObsidianQProvider());

KEM kem = KEM.getInstance("ML-KEM-768", "ObsidianQ");
KEM.Encapsulator enc = kem.newEncapsulator(publicKey);
KEM.Encapsulated result = enc.encapsulate();

SecretKey sharedSecret = result.key();           // 32-byte AES key
byte[] ciphertext = result.encapsulation();      // 1088 bytes
byte[] params = result.params();                 // Algorithm parameters
```

### Legacy Support (Java 8+)
For environments that haven't upgraded to Java 21, the legacy JCA mapping is still available:
- `KeyPairGenerator.getInstance("Kyber768")` — Key generation
- `KeyGenerator.getInstance("Kyber768")` — Encapsulation
- `KeyAgreement.getInstance("Kyber768")` — Decapsulation

---

## 6. Production Deployment Guide

### Step 1: Build the JAR
```bash
mvn clean package -DskipTests
```
This produces `target/obsidianq-sdk-1.0.0-SNAPSHOT.jar` containing:
- All Java classes
- The native Rust library for your OS (embedded in `natives/`)

### Step 2: Add to Your Project
Copy the JAR to your project's classpath, or install to your local Maven repo:
```bash
mvn install -DskipTests
```

### Step 3: Register the Provider
```java
// Option A: Programmatic (recommended for applications)
Security.addProvider(new ObsidianQProvider());

// Option B: JVM-wide (add to java.security file)
// security.provider.N=com.obsidianq.jce.ObsidianQProvider
```

### Step 4: Use Standard Java APIs
No custom imports needed beyond the one-time provider registration. Use `KeyPairGenerator`, `KEM`, or the legacy `KeyGenerator`/`KeyAgreement` APIs.

---

## 7. Side-Channel Hardening

### Constant-Time Guarantees
All algebraic operations on secret data are implemented without data-dependent branching:
- **NTT butterfly operations** use fixed loop bounds
- **Montgomery reduction** uses arithmetic-only operations
- **Barrett reduction** uses pre-computed constants
- **Re-encryption comparison** uses constant-time byte comparison (XOR accumulator)

### dudect Verification
The `core-rust/benches/dudect_bench.rs` uses statistical analysis (Welch's t-test) to verify that NTT execution time is independent of input data class:
```bash
cargo bench --bench dudect_bench
```
A t-value below 4.5 confirms constant-time behavior at 99.9% confidence.

---

## 8. Current State & Changelog

### v0.1.0 (Current)
- ✅ Full FIPS 203 ML-KEM-768 math core in Rust
- ✅ JNI zero-copy bridge with DirectByteBuffer
- ✅ JCA Provider with KeyPairGenerator, KeyGenerator, KeyAgreement SPIs
- ✅ Java 21 `javax.crypto.KEM` integration (`KyberKEMSpi`)
- ✅ NIST KAT vector validation (initial)
- ✅ GitHub Actions CI (Linux, macOS, Windows)
- ✅ Zeroize-on-drop memory safety
- ✅ NativeExtractor for automatic library loading from JAR

### Upcoming
- 🔄 Full NIST KAT vector suite
- 🔄 dudect constant-time statistical verification
- 🔄 Maven Central publication
- 🔄 Formal security audit
