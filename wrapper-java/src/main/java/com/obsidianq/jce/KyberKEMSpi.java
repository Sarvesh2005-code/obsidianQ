package com.obsidianq.jce;

import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Java 21 KEMSpi implementation for ML-KEM-768.
 * 
 * This provides native integration with the standard {@code javax.crypto.KEM} API
 * introduced in JEP 452, enabling quantum-safe key encapsulation through the
 * standard Java cryptographic framework.
 *
 * Usage:
 * <pre>
 *   KEM kem = KEM.getInstance("ML-KEM-768", "ObsidianQ");
 *   KEM.Encapsulator enc = kem.newEncapsulator(publicKey);
 *   KEM.Encapsulated result = enc.encapsulate();
 * </pre>
 */
public final class KyberKEMSpi implements KEMSpi {

    /** ML-KEM-768 public key size in bytes */
    private static final int PK_BYTES = 1184;
    /** ML-KEM-768 secret key size in bytes */
    private static final int SK_BYTES = 2400;
    /** ML-KEM-768 ciphertext size in bytes */
    private static final int CT_BYTES = 1088;
    /** Shared secret size in bytes */
    private static final int SS_BYTES = 32;

    public KyberKEMSpi() {
        // Ensure native library is loaded
        com.obsidianq.ObsidianNativeBridge.class.getName();
    }

    @Override
    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
                                                  AlgorithmParameterSpec spec,
                                                  SecureRandom secureRandom) {
        if (!(publicKey instanceof KyberPublicKey)) {
            throw new InvalidParameterException(
                "Expected KyberPublicKey, got " + publicKey.getClass().getName());
        }
        return new KyberEncapsulatorSpi((KyberPublicKey) publicKey);
    }

    @Override
    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
                                                  AlgorithmParameterSpec spec) {
        if (!(privateKey instanceof KyberPrivateKey)) {
            throw new InvalidParameterException(
                "Expected KyberPrivateKey, got " + privateKey.getClass().getName());
        }
        return new KyberDecapsulatorSpi((KyberPrivateKey) privateKey);
    }

    // =========================================================================
    // Encapsulator
    // =========================================================================

    private static final class KyberEncapsulatorSpi implements KEMSpi.EncapsulatorSpi {

        private final KyberPublicKey publicKey;

        KyberEncapsulatorSpi(KyberPublicKey publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        public javax.crypto.KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            // Allocate off-heap buffers for zero-copy native interaction
            ByteBuffer pkBuf = ByteBuffer.allocateDirect(PK_BYTES);
            ByteBuffer ctBuf = ByteBuffer.allocateDirect(CT_BYTES);
            ByteBuffer ssBuf = ByteBuffer.allocateDirect(SS_BYTES);

            // Load the public key into the direct buffer
            pkBuf.put(publicKey.getEncoded());
            pkBuf.flip();

            // Execute native encapsulation across the JNI boundary
            int result = com.obsidianq.ObsidianNativeBridge.encapsulateSecret(pkBuf, ctBuf, ssBuf);
            if (result != 0) {
                throw new SecurityException("Native ML-KEM encapsulation failed (code: " + result + ")");
            }

            // Extract the shared secret
            byte[] ssBytes = new byte[SS_BYTES];
            ssBuf.get(ssBytes);

            // Apply range selection per KEMSpi contract
            byte[] selectedSecret;
            if (from == 0 && to == SS_BYTES) {
                selectedSecret = ssBytes;
            } else {
                int len = to - from;
                selectedSecret = new byte[len];
                System.arraycopy(ssBytes, from, selectedSecret, 0, len);
            }

            String alg = (algorithm != null) ? algorithm : "AES";
            SecretKey key = new SecretKeySpec(selectedSecret, alg);

            // Extract the ciphertext
            byte[] ctBytes = new byte[CT_BYTES];
            ctBuf.get(ctBytes);

            return new javax.crypto.KEM.Encapsulated(key, ctBytes, null);
        }

        @Override
        public int engineSecretSize() {
            return SS_BYTES;
        }

        @Override
        public int engineEncapsulationSize() {
            return CT_BYTES;
        }
    }

    // =========================================================================
    // Decapsulator
    // =========================================================================

    private static final class KyberDecapsulatorSpi implements KEMSpi.DecapsulatorSpi {

        private final KyberPrivateKey privateKey;

        KyberDecapsulatorSpi(KyberPrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm) {
            if (encapsulation == null || encapsulation.length != CT_BYTES) {
                throw new IllegalArgumentException(
                    "Ciphertext must be exactly " + CT_BYTES + " bytes, got " +
                    (encapsulation == null ? "null" : encapsulation.length));
            }

            // Allocate off-heap buffers
            ByteBuffer ctBuf = ByteBuffer.allocateDirect(CT_BYTES);
            ByteBuffer skBuf = ByteBuffer.allocateDirect(SK_BYTES);
            ByteBuffer ssBuf = ByteBuffer.allocateDirect(SS_BYTES);

            // Load ciphertext and secret key into direct buffers
            ctBuf.put(encapsulation);
            ctBuf.flip();

            skBuf.put(privateKey.getEncoded());
            skBuf.flip();

            // Execute native decapsulation across the JNI boundary
            int result = com.obsidianq.ObsidianNativeBridge.decapsulateSecret(ctBuf, skBuf, ssBuf);
            if (result != 0) {
                throw new SecurityException("Native ML-KEM decapsulation failed (code: " + result + ")");
            }

            // Extract the shared secret
            byte[] ssBytes = new byte[SS_BYTES];
            ssBuf.get(ssBytes);

            // Apply range selection per KEMSpi contract
            byte[] selectedSecret;
            if (from == 0 && to == SS_BYTES) {
                selectedSecret = ssBytes;
            } else {
                int len = to - from;
                selectedSecret = new byte[len];
                System.arraycopy(ssBytes, from, selectedSecret, 0, len);
            }

            String alg = (algorithm != null) ? algorithm : "AES";
            return new SecretKeySpec(selectedSecret, alg);
        }

        @Override
        public int engineSecretSize() {
            return SS_BYTES;
        }

        @Override
        public int engineEncapsulationSize() {
            return CT_BYTES;
        }
    }
}
