# ObsidianQ Full Project Audit — Bugs, Security Issues & Improvements

> Comprehensive analysis of the entire ObsidianQ ML-KEM-768 codebase across Rust core, Java wrapper, CI, and documentation.

---

## 🔴 CRITICAL BUGS (Cryptographic Correctness)

These bugs cause **incorrect cryptographic output** and must be fixed before any other work.

---

### CRIT-1: `ZETAS` Table Values Do Not Match Reference Implementation

> [!CAUTION]
> This affects **every NTT and INTT computation** in the entire library. All polynomial multiplications produce wrong results.

**File:** [ntt.rs](file:///c:/Dev/Projects/Web-Projects/obsidianQ/core-rust/src/ntt.rs#L6-L15)

The ZETAS array does not match the canonical [pqcrystals/kyber](https://github.com/pq-crystals/kyber/blob/main/ref/ntt.c) reference values. For example:

| Index | Our Value | Reference (mod 3329) | Match? |
|-------|-----------|----------------------|--------|
| 0 | 2285 | 2285 (-1044) | ✅ |
| 1 | **2586** | **2571** (-758) | ❌ |
| 2 | **2560** | **2970** (-359) | ❌ |
| 3 | **2221** | **1812** | ❌ |

**Fix:** Regenerate all 128 ZETAS values using the reference implementation's bit-reversed primitive 17th root of unity in Montgomery domain. The `gen_zetas.rs` example should be updated to produce the canonical values and the output validated against the reference C implementation.

---

### CRIT-2: `inv_ntt` Butterfly Subtraction Has Inverted Sign

**File:** [ntt.rs](file:///c:/Dev/Projects/Web-Projects/obsidianQ/core-rust/src/ntt.rs#L64-L68)

```diff
 // Reference (correct):
-poly[j + len] = t - poly[j + len];
+poly[j + len] = poly[j + len] - t;
 poly[j + len] = montgomery_reduce((zeta as i32) * (poly[j + len] as i32));
```

The Gentleman-Sande butterfly for the inverse NTT computes `r[j+len] - t` (current minus saved), but our code computes `t - r[j+len]` (saved minus current). This negates the difference before the twiddle factor multiplication, producing incorrect inverse transforms.

**Reference:** [pqcrystals/kyber/ref/ntt.c:invntt()](https://github.com/pq-crystals/kyber/blob/main/ref/ntt.c#L62)

---

### CRIT-3: KAT Test Is a Complete Stub (Zero Validation)

**File:** [kat_test.rs](file:///c:/Dev/Projects/Web-Projects/obsidianQ/core-rust/tests/kat_test.rs#L43-L55)

The only test file in `tests/` has:
- Only **2 bytes** of seed data (`"e3b9"`) — a real KAT vector requires ≥64 bytes
- The actual KEM function call is **commented out** (line 51)
- The assertion is **commented out** (line 54)
- The test body does literally nothing useful

**Fix:** Implement real NIST KAT vectors from the [FIPS 203 validation files](https://csrc.nist.gov/Projects/post-quantum-cryptography). At minimum, inject deterministic d/z seeds, run keygen+encap+decap, and compare output byte-for-byte against known-good results.

---

## 🟠 SECURITY VULNERABILITIES

> [!WARNING]
> These issues compromise the security properties that ObsidianQ advertises.

---

### SEC-1: **~20 Debug `println!()` Statements Leak Secret Material** 🔥

**File:** [indcpa.rs](file:///c:/Dev/Projects/Web-Projects/obsidianQ/core-rust/src/indcpa.rs)

The IND-CPA module prints:
- Secret key polynomial coefficients (lines 62, 70, 72, 77, 85, 89)
- Internal NTT state during encryption (lines 111, 117, 138, 146, 148, 152, 154, 159, 163)
- Internal NTT state during decryption (lines 178, 182, 184, 189, 193–196, 199, 202)

**Impact:** Any process capturing stdout (logging, CI, containers) will have the complete secret key and all intermediate cryptographic state. This is a **total key compromise**.

**Fix:** Remove every `println!()` from production crypto code. Use `#[cfg(test)]` or `log::trace!` behind a compile-time feature flag if debug output is needed during development.

---

### SEC-2: Private Key Copied to Java Heap — Defeats Off-Heap Security Model

**File:** [KyberPrivateKey.java](file:///c:/Dev/Projects/Web-Projects/obsidianQ/wrapper-java/src/main/java/com/obsidianq/jce/KyberPrivateKey.java#L17-L22)

```java
public KyberPrivateKey(ByteBuffer buffer) {
    this.encoded = new byte[buffer.capacity()];
    buffer.get(this.encoded);  // ← Copies 2400 bytes of secret key ONTO the heap
}
```

The README and HANDBOOK claim "keys live off-heap in Rust buffers — invisible to GC, zeroized on drop." But `KyberPrivateKey` immediately copies the entire secret key to a `byte[]` on the JVM heap, where:
1. The GC can copy it freely during compaction
2. It appears in heap dumps (`.hprof`)
3. Memory scrapers can find it

**Fix:** Store only a reference/handle to native memory. Implement a JNI callback pattern where the private key bytes stay in Rust and operations are delegated to native code.

---

### SEC-3: No Panic Safety at JNI Boundary — Undefined Behavior

**File:** [lib.rs](file:///c:/Dev/Projects/Web-Projects/obsidianQ/core-rust/src/lib.rs)

If any Rust code panics (array bounds, integer overflow, etc.), the panic will unwind across the JNI boundary into undefined behavior — potentially crashing the JVM or corrupting memory.

**Fix:** Wrap every JNI function body in `std::panic::catch_unwind()`:
```rust
pub extern "system" fn Java_...(env: JNIEnv, ...) -> jint {
    match std::panic::catch_unwind(|| { /* body */ }) {
        Ok(result) => result,
        Err(_) => -2, // panic code
    }
}
```

---

### SEC-4: `KyberEncapsulatedSecret.getEncoded()` Returns Internal Reference

**File:** [KyberEncapsulatedSecret.java](file:///c:/Dev/Projects/Web-Projects/obsidianQ/wrapper-java/src/main/java/com/obsidianq/jce/KyberEncapsulatedSecret.java#L24-L27)

```java
public byte[] getEncoded() {
    return secret;  // ← Returns raw internal array, not a clone!
}
```

Callers can mutate the shared secret bytes directly. Compare with `KyberPublicKey.getEncoded()` which correctly returns `this.encoded.clone()`.

**Fix:** Return `secret.clone()` and `ciphertext.clone()` from both getters. Also implement `Destroyable` and zeroize on `destroy()`.

---

### SEC-5: DirectByteBuffers Not Zeroized After JNI Calls

**File:** [KyberKEMSpi.java](file:///c:/Dev/Projects/Web-Projects/obsidianQ/wrapper-java/src/main/java/com/obsidianq/jce/KyberKEMSpi.java#L74-L112)

After `encapsulateSecret()` completes, the `pkBuf`, `ctBuf`, and `ssBuf` DirectByteBuffers retain secret material in native memory. They are never explicitly zeroed.

**Fix:** After extracting results, zero-fill all DirectByteBuffers:
```java
finally {
    zeroBuffer(ssBuf);
    zeroBuffer(skBuf);
}
```

---

### SEC-6: NativeExtractor Uses Predictable Temp Path

**File:** [NativeExtractor.java](file:///c:/Dev/Projects/Web-Projects/obsidianQ/wrapper-java/src/main/java/com/obsidianq/util/NativeExtractor.java#L39-L45)

The temp file uses `Files.createTempFile("obsidian_core_", ".lib")` with no integrity check. An attacker with write access to the temp directory could race to replace the extracted library.

**Fix:** Verify the library checksum before `System.load()`, or extract to a directory with restrictive permissions.

---

### SEC-7: Rejection Sampling May Not Fill All 256 Coefficients

**File:** [indcpa.rs](file:///c:/Dev/Projects/Web-Projects/obsidianQ/core-rust/src/indcpa.rs#L21-L41)

```rust
// Rejection sampling is complex, we use a simplified version for demonstration
let buf = xof_absorb_squeeze(seed, x, y, 3 * KYBER_N); // 768 bytes
```

The comment admits this is "simplified for demonstration." If rejection sampling doesn't produce 256 valid coefficients within 768 bytes, the remaining coefficients stay at 0 — silently producing a **weak matrix A** that undermines the entire lattice security assumption.

**Fix:** Implement proper streaming rejection sampling with multiple squeeze rounds from the SHAKE-128 XOF, as specified in FIPS 203 Algorithm 6.

---

## 🟡 CODE QUALITY ISSUES

---

### CQ-1: Stray/Orphan Files Clutter the Repo

| File | Issue |
|------|-------|
| `core-rust/ntt_ref.c` | Empty file (0 bytes) |
| `core-rust/test_zetas.rs` | Loose file in project root, not in src/bin/examples/tests |
| `core-rust/examples/gen_zetas.rs` | Development artifact, should be a proper tool |
| `core-rust/examples/test_zetas2.rs` | Incomplete debug script |
| `core-rust/src/bin/test_zetas.rs` | One-off debug binary |

**Fix:** Delete orphan files. Move useful generators to a `tools/` directory or behind a cargo feature flag.

---

### CQ-2: CI Pipeline Doesn't Run Tests

**File:** [ci.yml](file:///c:/Dev/Projects/Web-Projects/obsidianQ/.github/workflows/ci.yml#L51-L52)

```yaml
- name: Maven Build & Test
  run: mvn clean test-compile -B  # ← Only COMPILES tests, never RUNS them
```

**Fix:** Change to `mvn clean verify -B` or `mvn clean test -B`.

---

### CQ-3: Release Bundle Doesn't Actually Bundle Cross-Platform Natives

**File:** [ci.yml](file:///c:/Dev/Projects/Web-Projects/obsidianQ/.github/workflows/ci.yml#L78-L99)

The `release-bundle` job downloads native artifacts from all three OS matrix builds, copies them to `assembled/natives/`, but then **rebuilds the Rust lib for Ubuntu only** and packages that. The downloaded cross-platform natives are never injected into the JAR.

**Fix:** Copy `assembled/natives/*` into `target/classes/natives/` before `mvn package`.

---

### CQ-4: `KyberDecapsulationSpi` Has Broken Stub Methods

**File:** [KyberDecapsulationSpi.java](file:///c:/Dev/Projects/Web-Projects/obsidianQ/wrapper-java/src/main/java/com/obsidianq/jce/KyberDecapsulationSpi.java#L76-L83)

```java
protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws ShortBufferException {
    return 0;  // ← Should copy secret bytes and return length
}

protected SecretKey engineGenerateSecret(String algorithm) {
    return null;  // ← Should wrap bytes in SecretKeySpec
}
```

These are required `KeyAgreementSpi` methods. Returning 0/null will silently break any code that uses these overloads.

---

### CQ-5: Deprecated `AccessController.doPrivileged` Usage

**File:** [ObsidianQProvider.java](file:///c:/Dev/Projects/Web-Projects/obsidianQ/wrapper-java/src/main/java/com/obsidianq/jce/ObsidianQProvider.java#L34-L38)

`AccessController` is deprecated for removal since Java 17 and the Security Manager is removed in Java 24. The `@SuppressWarnings("removal")` just hides the warning.

**Fix:** Remove the `AccessController.doPrivileged` wrapper entirely and call `bindCryptoEngines()` directly.

---

### CQ-6: Clone-Based `add`/`sub` API Causes Unnecessary Copies

Throughout `indcpa.rs`:
```rust
pkpv.vec[i].add(&pkpv.vec[i].clone(), &e.vec[i]);
```

Cloning `self` just to pass it as an argument is wasteful. The `Poly` struct is 512 bytes.

**Fix:** Add `add_assign(&mut self, other: &Poly)` and `sub_assign` methods.

---

### CQ-7: `symmetric.rs` Functions Are Never Used

The helper functions `hash_h()`, `hash_g()`, `kdf()` in [symmetric.rs](file:///c:/Dev/Projects/Web-Projects/obsidianQ/core-rust/src/symmetric.rs) are defined but **never called** from `kem.rs`, which constructs its own SHA3 hashers directly. This defeats the abstraction layer.

**Fix:** Refactor `kem.rs` to use `hash_h()`, `hash_g()`, `kdf()` from `symmetric.rs`. This centralizes the hash implementations for easier auditing.

---

### CQ-8: Barrett Reduce Recomputes Constant Every Call

**File:** [reduce.rs](file:///c:/Dev/Projects/Web-Projects/obsidianQ/core-rust/src/reduce.rs#L23)

```rust
let v = ((1i32 << 26) / (KYBER_Q as i32) + 1) as i16;  // recomputed on every call
```

**Fix:** Declare `const BARRETT_V: i16 = 20159;` as a module-level constant.

---

### CQ-9: No `#[cfg(test)]` Module, No Unit Tests in Rust Core

The Rust core has **zero unit tests** (no `#[cfg(test)] mod tests { ... }` in any file). The only test is the broken KAT stub. Individual functions (Montgomery, Barrett, CBD, NTT, pack/unpack) should each have targeted unit tests.

---

## 🔵 ARCHITECTURE IMPROVEMENTS

---

### ARCH-1: No Proper Streaming Rejection Sampling for Matrix Generation

The current `gen_matrix` pre-allocates a fixed buffer and hopes it's enough. FIPS 203 requires a streaming XOF that squeezes additional blocks on demand.

---

### ARCH-2: Hardcoded Constants Prevent Multi-Parameter Support

All ML-KEM parameters (K=3, η=2, du=10, dv=4) are hardcoded. There's no clean path to add ML-KEM-512 (K=2) or ML-KEM-1024 (K=4) without duplicating the entire codebase.

**Fix:** Use const generics or a `KyberParams` trait to parameterize the implementation.

---

### ARCH-3: No Proper Error Types — Everything Panics or Returns -1

The Rust core has no `Result` types. The JNI boundary returns raw `jint` status codes with no way to convey what went wrong.

**Fix:** Define an `enum KyberError` and propagate errors via `Result`. Map to JNI exceptions at the boundary.

---

### ARCH-4: No `module-info.java` for JPMS

The project targets Java 21 but doesn't provide a proper `module-info.java`. The `Automatic-Module-Name` manifest entry is a compatibility shim, not a real module descriptor.

---

### ARCH-5: Missing `isDestroyed()` on Key Classes

Both `KyberPublicKey` and `KyberPrivateKey` implement `Destroyable` but don't override `isDestroyed()`, so callers have no way to check the key's lifecycle state.

---

## Proposed Fix Priority Order

| Priority | Ticket | Effort | Impact |
|----------|--------|--------|--------|
| **P0** | SEC-1: Remove println leaks | 15 min | Eliminates total key compromise |
| **P0** | CRIT-1: Fix ZETAS table | 2-3 hr | All NTT math becomes correct |
| **P0** | CRIT-2: Fix inv_ntt sign | 5 min | INTT produces correct results |
| **P0** | CRIT-3: Implement real KAT tests | 3-4 hr | Validates entire pipeline |
| **P1** | SEC-2: Fix private key heap copy | 2-3 hr | Restores off-heap security claim |
| **P1** | SEC-3: Add panic safety to JNI | 1 hr | Prevents JVM crashes |
| **P1** | SEC-7: Fix rejection sampling | 2 hr | Ensures matrix A is fully populated |
| **P1** | CQ-2: Fix CI to run tests | 10 min | CI actually validates correctness |
| **P2** | SEC-4–6: Other security fixes | 2 hr | Defense-in-depth |
| **P2** | CQ-3–9: Code quality fixes | 3-4 hr | Maintainability |
| **P3** | ARCH-1–5: Architecture improvements | 1-2 weeks | Extensibility & production readiness |

---

## Verification Plan

### Automated Tests
1. `cargo test --release` — Rust unit tests and KAT vectors
2. `cargo run --example indcpa_test` — IND-CPA round-trip
3. `cargo run --example test_ntt` — NTT/INTT identity verification
4. `cargo bench --bench dudect_bench` — Constant-time verification
5. `mvn clean verify` — Full Java build + test cycle

### Manual Verification
- Compare ZETAS output byte-for-byte against [pqcrystals/kyber reference](https://github.com/pq-crystals/kyber/blob/main/ref/ntt.c)
- Run the IND-CPA encryption/decryption round-trip and verify message recovery
- Cross-reference KAT vectors against NIST test vectors
