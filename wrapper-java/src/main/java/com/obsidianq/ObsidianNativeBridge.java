package com.obsidianq;

import java.nio.ByteBuffer;

public class ObsidianNativeBridge {
    
    static {
        com.obsidianq.util.NativeExtractor.loadLibrary(); 
    }

    /**
     * Key Generation Phase. Fills the pre-allocated direct byte buffers with
     * the ML-KEM-768 public key (1184 bytes) and secret key (2400 bytes).
     */
    public static native int generateKeyPair(ByteBuffer pkBuffer, ByteBuffer skBuffer);

    /**
     * Encapsulation Phase. Takes the public key and generates a 1088-byte ciphertext
     * along with the derived 32-byte shared secret.
     */
    public static native int encapsulateSecret(ByteBuffer pkBuffer, ByteBuffer ctBuffer, ByteBuffer ssBuffer);

    /**
     * Decapsulation Phase. Takes the ciphertext and secret key to unmap and
     * derive the exact 32-byte shared secret originally created during encapsulation.
     */
    public static native int decapsulateSecret(ByteBuffer ctBuffer, ByteBuffer skBuffer, ByteBuffer ssBuffer);

    /**
     * Hardening Phase. Securely zeroizes a DirectByteBuffer from the native side
     * to ensure sensitive key material is immediately purged from RAM without
     * waiting for Garbage Collection or OS reclamation.
     */
    public static native void zeroizeBuffer(ByteBuffer buffer);
}
