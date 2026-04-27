package com.obsidianq.jce;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Maps Kyber Decapsulation math to Java 8's KeyAgreementSpi.
 * Retrieves the exact 32-byte shared secret utilizing the local PrivateKey 
 * and the network-provided Ciphertext, relying identically on NTT algebra.
 */
public class KyberDecapsulationSpi extends KeyAgreementSpi {
    private KyberPrivateKey localPrivateKey;
    private byte[] remoteCiphertext;

    @Override
    protected void engineInit(Key key, SecureRandom random) {
        if (key instanceof KyberPrivateKey) {
            this.localPrivateKey = (KyberPrivateKey) key;
        } else {
            throw new IllegalArgumentException("Key must be a KyberPrivateKey");
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) {
        engineInit(key, random);
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) {
        if (!lastPhase) {
            throw new IllegalStateException("Kyber is a KEM, doPhase must be called with lastPhase=true");
        }
        if (key != null && key.getEncoded() != null) {
            this.remoteCiphertext = key.getEncoded();
        } else {
            throw new IllegalArgumentException("Invalid ciphertext key provided");
        }
        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() {
        if (localPrivateKey == null || remoteCiphertext == null) {
            throw new IllegalStateException("Decapsulation not fully initialized with PrivateKey and Ciphertext");
        }

        java.nio.ByteBuffer ctBuffer = null;
        java.nio.ByteBuffer skBuffer = null;
        java.nio.ByteBuffer ssBuffer = null;

        try {
            ctBuffer = java.nio.ByteBuffer.allocateDirect(1088);
            ctBuffer.put(remoteCiphertext);
            ctBuffer.flip();

            skBuffer = java.nio.ByteBuffer.allocateDirect(2400);
            byte[] skBytes = localPrivateKey.getRawBytes();
            if (skBytes != null) {
                skBuffer.put(skBytes);
                skBuffer.flip();
            }

            ssBuffer = java.nio.ByteBuffer.allocateDirect(32);

            int status = com.obsidianq.ObsidianNativeBridge.decapsulateSecret(ctBuffer, skBuffer, ssBuffer);
            if (status != 0) {
                throw new RuntimeException("NTT Decapsulation Failed");
            }

            byte[] ssBytes = new byte[32];
            ssBuffer.get(ssBytes);
            return ssBytes;
        } finally {
            if (ctBuffer != null) com.obsidianq.ObsidianNativeBridge.zeroizeBuffer(ctBuffer);
            if (skBuffer != null) com.obsidianq.ObsidianNativeBridge.zeroizeBuffer(skBuffer);
            if (ssBuffer != null) com.obsidianq.ObsidianNativeBridge.zeroizeBuffer(ssBuffer);
        }
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws ShortBufferException {
        return 0;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) {
        return null; // Will wrap the raw bytes in a generic AES or ChaCha20 SecretKeySpec
    }
}
