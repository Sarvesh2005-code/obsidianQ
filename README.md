# ObsidianQ SDK

**ObsidianQ** is a quantum-safe cryptographic SDK designed to integrate the NIST FIPS 203 Post-Quantum Cryptography standard (CRYSTALS-Kyber / ML-KEM) natively into the Java ecosystem. 

It achieves state-of-the-art performance and strict memory safety by writing the rigorous mathematical lattice cryptography in **Rust** and bridging it to the **Java Cryptography Architecture (JCA)** via zero-copy JNI/FFI boundaries.

## Core Features

- **Post-Quantum Security:** Implements NIST ML-KEM-768 parameters to defend against "Store Now, Decrypt Later" quantum computing threats.
- **Off-Heap Memory Safety:** Volatile cryptographic keys are stored natively in Rust buffers outside of the JVM's Garbage Collector. This mitigates cold-boot attacks and accidental heap leakage.
- **Zero-Copy Architecture:** The JVM interacts with the native Rust layer via `java.nio.DirectByteBuffer`, ensuring memory stability and high performance during constant-time Number Theoretic Transforms (NTT).
- **JCA Compliant:** Acts as a drop-in replacement for any legacy application utilizing Java's standard `KeyPairGenerator`, `KeyGenerator`, and `KeyAgreement` Security Provider Interfaces (SPI).

## Architecture
The SDK consists of two primary modules:
1. `core-rust/`: The Rust cryptographic core implementing the FIPS 203 primitives, NTT algorithms, and Montgomery/Barrett reductions.
2. `wrapper-java/`: The Java Maven project that packages the `ObsidianNativeBridge` and provides the JCA service configurations.

## Build and Test
Requirements:
- Java JDK 8 or higher
- Maven
- Rust and Cargo (latest stable)

To build and run the structural Key Encapsulation integration test:
```bash
mvn clean test-compile exec:java "-Dexec.mainClass=com.obsidianq.JCAIntegrityTest" "-Dexec.classpathScope=test"
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
