package com.obsidianq.jce;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Maps the Kyber Encapsulation math to Java 8's KeyGeneratorSpi.
 * 
 * In ML-KEM, encapsulation generates both:
 * 1. A 32-byte Shared Secret (the AES/ChaCha Key)
 * 2. A 1088-byte Ciphertext (to literally send across the network)
 * 
 * Since Java 8 expects KeyGenerators to only return a SecretKey,
 * we mathematically encode both coordinates into a custom SecretKey interface
 * that the user can unpack. 
 */
public class KyberEncapsulationSpi extends KeyGeneratorSpi {
    
    @Override
    protected void engineInit(SecureRandom random) {
        throw new UnsupportedOperationException("Kyber Encapsulation fundamentally requires a PublicKey to initialize.");
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) {
        // Here we intercept the parameter spec containing the remote peer's PublicKey
        // and prime the Rust NTT Engine via JNI for the Encapsulation operation.
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        throw new UnsupportedOperationException("Keysize is fixed mathematically by ML-KEM-768.");
    }

    @Override
    protected SecretKey engineGenerateKey() {
        // Will pipe down into our core-rust zeroized encapsulation method
        return null;
    }
}
