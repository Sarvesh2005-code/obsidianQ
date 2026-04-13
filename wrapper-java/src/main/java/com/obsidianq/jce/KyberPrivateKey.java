package com.obsidianq.jce;

import java.security.PrivateKey;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * ML-KEM Private Key containing the polynomial vector `s` and Decapsulation key `z`.
 * Extremely volatile. Must strictly honor explicit JCA destroy() methods 
 * to coordinate with our Rust engine's Zeroize traits.
 */
public class KyberPrivateKey implements PrivateKey, javax.security.auth.Destroyable {
    
    private final byte[] encoded;
    private boolean destroyed = false;

    public KyberPrivateKey(ByteBuffer buffer) {
        // While the core memory is protected in Rust via Off-Heap zeroization,
        // legacy JCE components often request getEncoded(). We must manually zero-out
        // this heap projection the moment JCA Destroyable.destroy() is invoked.
        this.encoded = new byte[buffer.capacity()];
        buffer.get(this.encoded);
    }

    @Override
    public String getAlgorithm() {
        return "Kyber768";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        return destroyed ? null : this.encoded.clone();
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            Arrays.fill(this.encoded, (byte) 0);
            this.destroyed = true;
        }
    }
}
