package com.obsidianq.jce;

import java.security.Provider;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * The core Java Cryptography Architecture (JCA) Provider for ObsidianQ.
 * 
 * Registers ML-KEM-768 (CRYSTALS-Kyber) cryptographic services into the JVM,
 * supporting both the modern Java 21 {@code javax.crypto.KEM} API and legacy
 * JCA interfaces for backward compatibility.
 *
 * Usage:
 * <pre>
 *   Security.addProvider(new ObsidianQProvider());
 *   
 *   // Java 21+ (recommended)
 *   KEM kem = KEM.getInstance("ML-KEM-768", "ObsidianQ");
 *   
 *   // Legacy (Java 8+)
 *   KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber768", "ObsidianQ");
 * </pre>
 */
public final class ObsidianQProvider extends Provider {
    
    private static final long serialVersionUID = 1L;
    public static final String PROVIDER_NAME = "ObsidianQ";

    public ObsidianQProvider() {
        super(PROVIDER_NAME, "1.0", 
            "ObsidianQ Post-Quantum Cryptography Provider — NIST FIPS 203 (ML-KEM/Kyber)");
        
        @SuppressWarnings("removal")
        var dummy = AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            bindCryptoEngines();
            return null;
        });
    }

    /**
     * Registers all cryptographic service implementations.
     */
    private void bindCryptoEngines() {
        // ── Java 21 KEM API (JEP 452) ───────────────────────────────
        put("KEM.ML-KEM-768", "com.obsidianq.jce.KyberKEMSpi");
        put("Alg.Alias.KEM.Kyber768", "ML-KEM-768");
        put("Alg.Alias.KEM.MLKEM768", "ML-KEM-768");

        // ── Legacy JCA Interfaces (Java 8+) ─────────────────────────
        // KeyPairGenerator: Lattice key generation
        put("KeyPairGenerator.Kyber768", "com.obsidianq.jce.KyberKeyPairGeneratorSpi");
        
        // KeyGenerator: Encapsulation (generates SharedSecret + Ciphertext)
        put("KeyGenerator.Kyber768", "com.obsidianq.jce.KyberEncapsulationSpi");
        
        // KeyAgreement: Decapsulation (recovers SharedSecret from Ciphertext + PrivateKey)
        put("KeyAgreement.Kyber768", "com.obsidianq.jce.KyberDecapsulationSpi");

        // ── OID Aliases ─────────────────────────────────────────────
        put("Alg.Alias.KeyPairGenerator.1.3.6.1.4.1.2.267.1.4.4", "Kyber768");
        put("Alg.Alias.KEM.1.3.6.1.4.1.22554.5.6.1", "ML-KEM-768");
    }
}
