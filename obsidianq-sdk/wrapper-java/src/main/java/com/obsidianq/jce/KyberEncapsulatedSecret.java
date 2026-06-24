package com.obsidianq.jce;

import javax.crypto.SecretKey;

public class KyberEncapsulatedSecret implements SecretKey {
    private final byte[] secret;
    private final byte[] ciphertext;

    public KyberEncapsulatedSecret(byte[] secret, byte[] ciphertext) {
        this.secret = secret;
        this.ciphertext = ciphertext;
    }

    @Override
    public String getAlgorithm() {
        return "Kyber768";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return secret;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }
}
