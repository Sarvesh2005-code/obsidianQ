package com.obsidianq.jce;

import java.security.Provider;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * The core Java Cryptography Architecture (JCA) Provider for ObsidianQ.
 * Acting as the mathematical bridge, this registers our lattice-based 
 * non-commutative algebraic structures into the legacy JVM environment.
 *
 * Usage:
 * Security.addProvider(new ObsidianQProvider());
 */
public final class ObsidianQProvider extends Provider {
    
    private static final long serialVersionUID = 1L;
    public static final String PROVIDER_NAME = "ObsidianQ";

    public ObsidianQProvider() {
        // Enforcing Java 8 compatibility constraint per PRD.
        super(PROVIDER_NAME, 1.0, 
            "ObsidianQ Post-Quantum Cryptography Provider implementing NIST FIPS 203 (ML-KEM/Kyber)");
        
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                bindMathematicalEngines();
                return null;
            }
        });
    }

    /**
     * Binds the FIPS 203 Cryptographic primitives to the standard JCA interfaces.
     * Since Java 8 natively lacks a purely asymmetric Key Encapsulation Mechanism (KEM) SPI,
     * we mathematically map Encapsulation to an asymmetric KeyGenerator, 
     * and Decapsulation to a KeyAgreement.
     */
    private void bindMathematicalEngines() {
        // 1. Lattice Base Generation (Mod q polynomial matrices)
        put("KeyPairGenerator.Kyber768", "com.obsidianq.jce.KyberKeyPairGeneratorSpi");
        
        // 2. Encapsulation: Generates (SharedSecret, Ciphertext) upon ingestion of PublicKey
        put("KeyGenerator.Kyber768", "com.obsidianq.jce.KyberEncapsulationSpi");
        
        // 3. Decapsulation: Receives Ciphertext + PrivateKey to algebraically recover SharedSecret
        put("KeyAgreement.Kyber768", "com.obsidianq.jce.KyberDecapsulationSpi");

        // Object Identifiers (OIDs) for ASN.1 Parsing
        put("Alg.Alias.KeyPairGenerator.1.3.6.1.4.1.2.267.1.4.4", "Kyber768"); // Standard Draft OID Mapping
    }
}
