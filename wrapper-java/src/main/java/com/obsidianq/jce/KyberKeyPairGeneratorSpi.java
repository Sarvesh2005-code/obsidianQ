package com.obsidianq.jce;

import java.security.KeyPairGeneratorSpi;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import com.obsidianq.ObsidianNativeBridge;
import java.nio.ByteBuffer;

/**
 * Implements the mathematical matrix generation for a Kyber-768 key pair.
 * In ML-KEM, the keypair generation utilizes a secure random seed to expand into
 * a highly structured polynomial matrix via XOFs (like SHAKE-128).
 */
public class KyberKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private SecureRandom random;
    private boolean initialized = false;

    // FIPS 203 Dimension parameters for mathematically bounding memory constraints
    private static final int PUBLIC_KEY_CIPHERTEXT_BYTES = 1184;
    private static final int PRIVATE_KEY_BYTES = 2400; // Represents the compact Sk structure

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != 768) {
            throw new IllegalArgumentException("ObsidianQ currently enforces ML-KEM-768 strictly.");
        }
        this.random = random != null ? random : new SecureRandom();
        this.initialized = true;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) 
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Kyber768 relies purely on systemic randomness, no custom parameters accepted.");
    }

    @Override
    public KeyPair generateKeyPair() {
        if (!initialized) {
            initialize(768, new SecureRandom());
        }

        // 1. Off-Heap Malloc for keys. Bypassing GC as defined in Stage 1 architecture.
        ByteBuffer pkBuffer = ByteBuffer.allocateDirect(PUBLIC_KEY_CIPHERTEXT_BYTES);
        ByteBuffer skBuffer = ByteBuffer.allocateDirect(PRIVATE_KEY_BYTES);

        // 2. Transmit pointers across the memory boundary via JNI into the Rust NTT Engine.
        int status = ObsidianNativeBridge.generateKyberSecret(skBuffer, PRIVATE_KEY_BYTES); // Placeholder mapping
        
        if (status != 0) {
            throw new RuntimeException("Fatal Cryptographic Error: Lattice mapping failed during NTT expansion.");
        }

        // 3. Mathematical mapping into standard JCA objects
        KyberPublicKey publicKey = new KyberPublicKey(pkBuffer);
        KyberPrivateKey privateKey = new KyberPrivateKey(skBuffer);

        return new KeyPair(publicKey, privateKey);
    }
}
