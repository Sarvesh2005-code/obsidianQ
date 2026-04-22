# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in ObsidianQ, please report it responsibly:

1. **Email:** Contact the maintainer directly via GitHub profile.
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline
- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix & Disclosure:** Coordinated with the reporter

## Security Design Principles

ObsidianQ follows these security principles:

1. **Constant-Time Execution:** All operations on secret data (NTT, Montgomery reduction, Barrett reduction) are implemented without data-dependent branching.
2. **Off-Heap Key Storage:** Private keys and shared secrets are stored in native Rust memory, outside the JVM heap, preventing GC-based memory leakage.
3. **Zeroization:** All secret key structures implement `Zeroize` + `ZeroizeOnDrop` to ensure deterministic memory cleanup.
4. **No Secret Logging:** The codebase never logs, prints, or serializes private key material.
