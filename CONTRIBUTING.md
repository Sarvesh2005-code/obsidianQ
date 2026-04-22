# Contributing to ObsidianQ

Thank you for considering contributing to ObsidianQ! This project implements security-critical cryptographic primitives, so all contributions are held to a high standard.

## Getting Started

### Prerequisites
- **Rust** (stable, latest) — [rustup.rs](https://rustup.rs)
- **Java JDK 21+** — [Adoptium Temurin](https://adoptium.net)
- **Maven 3.9+** — [maven.apache.org](https://maven.apache.org)

### Building
```bash
# Clone the repository
git clone https://github.com/Sarvesh2005-code/obsidianQ.git
cd obsidianQ

# Build the Rust core
cargo build --release --manifest-path core-rust/Cargo.toml

# Build and test everything
mvn clean test-compile
```

### Running the Integrity Test
```bash
mvn exec:java "-Dexec.mainClass=com.obsidianq.JCAIntegrityTest" "-Dexec.classpathScope=test"
```

## Contribution Guidelines

### Security-Critical Code
This is a **cryptographic library**. Please observe:

1. **No branching on secret data.** All operations on keys and sensitive material must be constant-time.
2. **No heap copies of secrets.** Shared secrets and private keys must remain off-heap via `DirectByteBuffer`.
3. **Zeroize on drop.** Any Rust struct holding key material must derive `Zeroize` and `ZeroizeOnDrop`.
4. **No `println!` of secrets.** Never log, print, or serialize private key material, even in tests.

### Code Style
- **Rust:** Follow standard `rustfmt` formatting. Run `cargo fmt` before committing.
- **Java:** Follow standard Java conventions. No wildcard imports.

### Pull Request Process
1. Fork the repository and create a feature branch from `main`.
2. Write tests for any new functionality.
3. Ensure `cargo test --release` and `mvn clean test-compile` pass with zero warnings.
4. Submit your PR with a clear description of the changes and their security implications.

### Reporting Security Vulnerabilities
**Do NOT open a public issue for security vulnerabilities.** Instead, email the maintainer directly. We take all security reports seriously and will respond within 48 hours.

## Areas Where Help is Needed
- **Cross-platform testing** (Linux ARM64, macOS Apple Silicon)
- **NIST KAT vector validation** against the full FIPS 203 test suite
- **Performance benchmarks** against `liboqs` and `pqcrypto`
- **Documentation and examples** for different use cases (TLS, secure messaging, etc.)

## License
By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
