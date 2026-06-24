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
    
    private KyberPublicKey remotePublicKey;

    @Override
    protected void engineInit(SecureRandom random) {
        throw new UnsupportedOperationException("Kyber Encapsulation fundamentally requires a PublicKey to initialize.");
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) {
        if (params instanceof KyberParameterSpec) {
            java.security.PublicKey pk = ((KyberParameterSpec) params).getPublicKey();
            if (pk instanceof KyberPublicKey) {
                this.remotePublicKey = (KyberPublicKey) pk;
            }
        } else if (params instanceof KyberPublicKey) {
            this.remotePublicKey = (KyberPublicKey) params;
        }
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        throw new UnsupportedOperationException("Keysize is fixed mathematically by ML-KEM-768.");
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (remotePublicKey == null) {
            throw new IllegalStateException("Remote public key not set for encapsulation.");
        }
        
        java.nio.ByteBuffer pkBuffer = null;
        java.nio.ByteBuffer ctBuffer = null;
        java.nio.ByteBuffer ssBuffer = null;

        try {
            pkBuffer = java.nio.ByteBuffer.allocateDirect(1184);
            byte[] pkBytes = remotePublicKey.getRawBytes();
            if (pkBytes != null) {
                pkBuffer.put(pkBytes);
                pkBuffer.flip();
            }

            ctBuffer = java.nio.ByteBuffer.allocateDirect(1088);
            ssBuffer = java.nio.ByteBuffer.allocateDirect(32);

            int status = com.obsidianq.ObsidianNativeBridge.encapsulateSecret(pkBuffer, ctBuffer, ssBuffer);
            if (status != 0) {
                throw new RuntimeException("NTT Encapsulation Failed");
            }

            byte[] ssBytes = new byte[32];
            ssBuffer.get(ssBytes);
            
            byte[] ctBytes = new byte[1088];
            ctBuffer.get(ctBytes);

            return new KyberEncapsulatedSecret(ssBytes, ctBytes);
        } finally {
            if (pkBuffer != null) com.obsidianq.ObsidianNativeBridge.zeroizeBuffer(pkBuffer);
            if (ctBuffer != null) com.obsidianq.ObsidianNativeBridge.zeroizeBuffer(ctBuffer);
            if (ssBuffer != null) com.obsidianq.ObsidianNativeBridge.zeroizeBuffer(ssBuffer);
        }
    }
}
