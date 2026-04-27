package com.obsidianq.jce;

import com.obsidianq.jce.util.ASN1Util;
import java.security.PrivateKey;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * ML-KEM Private Key containing the polynomial vector {@code s} and Decapsulation key {@code z}.
 * Extremely volatile. Must strictly honor explicit JCA destroy() methods 
 * to coordinate with our Rust engine's Zeroize traits.
 *
 * <p>Implements the JCA {@link PrivateKey} contract by returning a PKCS#8
 * {@code PrivateKeyInfo} DER structure from {@link #getEncoded()},
 * using the NIST CSOR OID for ML-KEM-768 ({@code 2.16.840.1.101.3.4.4.2}).</p>
 *
 * <p>Internal consumers (e.g. the JNI bridge) that require the raw 2400-byte
 * secret key should use {@link #getRawBytes()} instead.</p>
 */
public class KyberPrivateKey implements PrivateKey, javax.security.auth.Destroyable {
    
    /** Raw ML-KEM-768 private key bytes (2400 bytes) */
    private final byte[] rawKey;

    /** Lazily computed PKCS#8 PrivateKeyInfo DER encoding */
    private volatile byte[] pkcs8Encoded;

    private boolean destroyed = false;

    public KyberPrivateKey(ByteBuffer buffer) {
        // While the core memory is protected in Rust via Off-Heap zeroization,
        // legacy JCE components often request getEncoded(). We must manually zero-out
        // this heap projection the moment JCA Destroyable.destroy() is invoked.
        this.rawKey = new byte[buffer.capacity()];
        buffer.get(this.rawKey);
    }

    /**
     * Returns the raw ML-KEM-768 private key bytes (2400 bytes).
     * This is the representation expected by the native JNI bridge.
     *
     * @return raw key bytes, or {@code null} if destroyed
     */
    public byte[] getRawBytes() {
        return destroyed ? null : this.rawKey.clone();
    }

    @Override
    public String getAlgorithm() {
        return "Kyber768";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * Returns the key encoded as a PKCS#8 PrivateKeyInfo DER structure.
     * This is the standard JCA format expected by KeyStores and
     * {@code KeyFactory.generatePrivate()}.
     *
     * @return DER-encoded PrivateKeyInfo, or {@code null} if destroyed
     */
    @Override
    public byte[] getEncoded() {
        if (destroyed) return null;
        byte[] cached = this.pkcs8Encoded;
        if (cached == null) {
            cached = ASN1Util.wrapPKCS8PrivateKey(this.rawKey);
            this.pkcs8Encoded = cached;
        }
        return cached.clone();
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            Arrays.fill(this.rawKey, (byte) 0);
            if (this.pkcs8Encoded != null) {
                Arrays.fill(this.pkcs8Encoded, (byte) 0);
            }
            this.destroyed = true;
        }
    }
}
