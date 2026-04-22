# ObsidianQ Handbook

Welcome to the ObsidianQ internal handbook. This document serves as a complete reference guide for understanding the project's vision, architecture, and structural decisions.

## 1. Project Vision
As quantum computing advances, classical cryptographic algorithms (RSA, ECC) are increasingly vulnerable to Shor's Algorithm. The industry is currently migrating to **Post-Quantum Cryptography (PQC)** standards defined by NIST. 

The goal of ObsidianQ is to provide enterprise Java applications with an immediate, drop-in replacement for their key encapsulation mechanisms (KEM) without compromising on memory safety or performance. By relying on Rust for the core mathematics, ObsidianQ prevents sensitive key material from lingering in the JVM's unpredictable Garbage Collection cycles.

## 2. Technical Stack
- **Rust Core:** Handles the lattice-based arithmetic, strict byte-packing, and constant-time execution of the Number Theoretic Transform (NTT).
- **JNI/FFI Bridge:** Connects Java to Rust.
- **Java Cryptography Architecture (JCA):** Exposes the capabilities seamlessly via the JVM standard `java.security.Provider` and Service Provider Interfaces (SPI).

## 3. The Memory Model (Zero-Copy)
To prevent JVM heap scanning attacks, all secret material is strictly stored off-heap:
1. Java uses `ByteBuffer.allocateDirect()` to request native memory blocks.
2. These memory addresses are handed off directly to Rust via JNI raw pointers.
3. Rust populates the keys and randomizes the entropy locally.
4. Java retrieves public parameters without copying the secret vector bounds.

## 4. Current State & Future Roadmap
Currently, ObsidianQ has established the structural pipelines, successfully routing data over the FFI boundary, handling JCA abstractions, and zeroizing memory buffers.

**Upcoming Milestones:**
- **Phase 1: Full FIPS 203 Math.** Implement SHAKE-128/256 expansions, CBD, and strict NTT matrix multiplications.
- **Phase 2: Side-Channel Hardening.** Integrate `dudect-rust` statistical analysis to guarantee constant-time execution paths without branching.
- **Phase 3: Java 21 Integration.** Modernize the wrapper to natively support `javax.crypto.KEM` for newer JVM architectures.
