package com.obsidianq.kms.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/kem")
public class KemController {

    private static final String ALGORITHM = "Kyber768";
    private static final String PROVIDER = "ObsidianQ";
    private static final String KEM_ALGORITHM = "ML-KEM-768";

    @PostMapping("/generate")
    public ResponseEntity<Map<String, String>> generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        KeyPair kp = kpg.generateKeyPair();

        String pubKeyBase64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        String privKeyBase64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());

        return ResponseEntity.ok(Map.of(
                "publicKey", pubKeyBase64,
                "privateKey", privKeyBase64
        ));
    }

    @PostMapping("/encapsulate")
    public ResponseEntity<Map<String, String>> encapsulate(@RequestBody Map<String, String> request) throws Exception {
        String pubKeyBase64 = request.get("publicKey");
        if (pubKeyBase64 == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "publicKey is required"));
        }

        byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

        KEM kem = KEM.getInstance(KEM_ALGORITHM, PROVIDER);
        KEM.Encapsulator enc = kem.newEncapsulator(publicKey);
        KEM.Encapsulated encapsulated = enc.encapsulate();

        String ciphertextBase64 = Base64.getEncoder().encodeToString(encapsulated.encapsulation());
        String sharedSecretBase64 = Base64.getEncoder().encodeToString(encapsulated.key().getEncoded());

        return ResponseEntity.ok(Map.of(
                "ciphertext", ciphertextBase64,
                "sharedSecret", sharedSecretBase64
        ));
    }

    @PostMapping("/decapsulate")
    public ResponseEntity<Map<String, String>> decapsulate(@RequestBody Map<String, String> request) throws Exception {
        String privKeyBase64 = request.get("privateKey");
        String ciphertextBase64 = request.get("ciphertext");
        
        if (privKeyBase64 == null || ciphertextBase64 == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "privateKey and ciphertext are required"));
        }

        byte[] privKeyBytes = Base64.getDecoder().decode(privKeyBase64);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privKeyBytes));

        KEM kem = KEM.getInstance(KEM_ALGORITHM, PROVIDER);
        KEM.Decapsulator dec = kem.newDecapsulator(privateKey);
        SecretKey secretKey = dec.decapsulate(ciphertext);

        String sharedSecretBase64 = Base64.getEncoder().encodeToString(secretKey.getEncoded());

        return ResponseEntity.ok(Map.of(
                "sharedSecret", sharedSecretBase64
        ));
    }
}
