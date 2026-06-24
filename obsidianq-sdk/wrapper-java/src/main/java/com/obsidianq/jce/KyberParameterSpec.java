package com.obsidianq.jce;

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public class KyberParameterSpec implements AlgorithmParameterSpec {
    private final PublicKey publicKey;

    public KyberParameterSpec(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
