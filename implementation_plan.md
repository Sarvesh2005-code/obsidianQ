# ObsidianQ: Quantum-Safe Drop-In SDK
## Implementation Plan & CTF Roadmap

This plan outlines the architecture and execution roadmap for ObsidianQ, translating the PRD into a strict, secure, and highly optimized technical strategy.

### 1. Architectural Strategy: The "Rust-Core / Java-Facade" Hybrid
As requested, we are abandoning pure Java for the core cryptographic algorithms. Pure Java poses extreme risks for constant-time math due to its Just-In-Time (JIT) compiler unpredictability and Garbage Collector (GC) behavior, which makes explicit, deterministic memory wiping nearly impossible.

**The Solution:**
*   **Core Cryptography Engine:** Built in **Rust**. Rust provides strict memory safety, zero-cost abstractions, deterministic compilation for constant-time execution, and specialized crates (e.g., `zeroize`) for explicit memory wiping.
*   **The Facade:** A **Java Cryptography Architecture (JCA) Provider**. The Java codebase will consist strictly of JNI bindings and classes implementing the standard `java.security.Provider`. This means a legacy application only has to run `Security.addProvider(new ObsidianQProvider());` to upgrade their entire system.
*   **Packaging:** We will compile the Rust core into native shared libraries (`.so`, `.dll`, `.dylib`) and bundle them inside a single `.jar` file. A lightweight resource extractor in the Java wrapper will load the correct native library at runtime natively—achieving the **zero-dependency** requirement.

---

### 2. Required Enhancements for Commercial Success
To elevate this from a GitHub project to an Enterprise-grade SDK:
1.  **Hybrid Cryptography (Kyber + X25519/NIST-ECC):** FIPS 203 deployments currently recommend combining Kyber with a classical algorithm (like ECDH or RSA-KEM). If Kyber is ever broken by new mathematical discoveries, the classic security remains as a fallback. We will implement this hybrid approach.
2.  **Pinned Memory / `DirectByteBuffer` Usage:** When passing plaintext/ciphertext from the JVM down to the Rust core, we must prevent the JVM from silently copying the byte arrays during garbage collection. We will use off-heap memory to ensure no ghost copies of keys exist in JVM RAM.

---

### 3. CTF Roadmap (The Execution Stages)
We will execute this project as a multi-stage Capture-The-Flag. You must complete each stage to advance.

*   **Stage 1: The Secure FFI Boundary (Rust ↔ Java).** 
    *   Initialize the Rust crate and the Java JNI bridge. Design a mechanism to allocate "pinned" memory that is shared between Java and Rust, preventing GC copying.
*   **Stage 2: Kyber's Heart - Number Theoretic Transform (NTT) in Rust.**
    *   Implement the fundamental polynomial arithmetic and matrix operations strictly in constant time according to FIPS 203.
*   **Stage 3: ML-KEM Generation, Encapsulation, Decapsulation.**
    *   Build the core protocols. Enforce explicit `zeroize` drops on all key materials upon function exit.
*   **Stage 4: The Drop-In JCA Wrapper.**
    *   Write the Java `javax.crypto.CipherSpi` and `java.security.KeyPairGeneratorSpi` implementations that natively call our Rust engine.
*   **Stage 5: Packaging & CI/CD.**
    *   Automate the cross-compilation of the Rust binaries and bundle them cleanly into the Java `.jar`.

---

## User Review Required
> [!IMPORTANT]
> Please review this architecture. Let me know if you approve the **Rust-JNI-Java** strategy to achieve absolute memory safety and constant-time math while preserving the legacy Java application "Drop-In" experience constraint. If approved, we will begin Stage 1.
