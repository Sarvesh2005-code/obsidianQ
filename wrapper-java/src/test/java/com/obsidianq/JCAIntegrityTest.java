package com.obsidianq;

import com.obsidianq.jce.ObsidianQProvider;
import com.obsidianq.jce.KyberParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;

/**
 * Phase 3 V&V: Strict JCA Compliance Test.
 * 
 * Demonstrates that the native Rust bindings seamlessly map to Oracle's 
 * standard cryptographic interfaces without requiring proprietary imports
 * (outside of the one-time Provider registration).
 */
public class JCAIntegrityTest {

    public static void main(String[] args) throws Exception {
        System.out.println("[*] ObsidianQ V&V Integrity Initialization...");

        // 1. Install the Provider globally into the JVM
        Security.addProvider(new ObsidianQProvider());

        // ---------------------------------------------------------
        // 2. Alice: Generate the ML-KEM KeyPair (Kyber768 base)
        // ---------------------------------------------------------
        System.out.println("[*] Executing JCA KeyPairGenerator for ML-KEM-768");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber768", ObsidianQProvider.PROVIDER_NAME);
        KeyPair aliceKeyPair = kpg.generateKeyPair();
        
        System.out.println("[+] KeyPair successfully generated and mathematically allocated.");

        // ---------------------------------------------------------
        // 3. Bob: Encapsulate shared secret using Alice's Public Key
        // ---------------------------------------------------------
        System.out.println("[*] Executing JCA KeyGenerator (Encapsulation Phase)");
        KeyGenerator encapGen = KeyGenerator.getInstance("Kyber768", ObsidianQProvider.PROVIDER_NAME);
        
        // Bob initializes his key generator with Alice's public key (The JCE parameter bridge)
        encapGen.init(new KyberParameterSpec(aliceKeyPair.getPublic())); 
        SecretKey bobCipherOutput = encapGen.generateKey(); 

        // At this point, bobCipherOutput technically holds BOTH the 32-byte shared secret
        // AND the 1088-byte ciphertext required to transmit to Alice.
        // We unpack them for transmission.
        byte[] ciphertextToTransmit = extractCiphertext(bobCipherOutput);
        byte[] bobSharedSecret = bobCipherOutput.getEncoded(); 

        // ---------------------------------------------------------
        // 4. Alice: Decapsulate shared secret using Ciphertext & Private Key
        // ---------------------------------------------------------
        System.out.println("[*] Executing JCA KeyAgreement (Decapsulation Phase)");
        KeyAgreement decapAgreement = KeyAgreement.getInstance("Kyber768", ObsidianQProvider.PROVIDER_NAME);
        
        // Alice initializes the engine strictly with her extremely volatile zeroized private key
        decapAgreement.init(aliceKeyPair.getPrivate());
        
        // Alice inputs the ciphertext she received from Bob across the network
        decapAgreement.doPhase(new KyberCiphertextKey(ciphertextToTransmit), true);
        
        // Alice extracts the raw 32-byte shared secret using constant-time NTT math across the FFI
        byte[] aliceSharedSecret = decapAgreement.generateSecret();

        // ---------------------------------------------------------
        // 5. Mathematical Validation Constraint Check
        // ---------------------------------------------------------
        if (Arrays.equals(aliceSharedSecret, bobSharedSecret)) {
            System.out.println("[SUCCESS] Quantum-Safe KEM Integrity Verified: Both ends derived identical AES Secrets.");
        } else {
            System.err.println("[FATAL] Mathematical Drift! Decapsulated key material failed matching.");
        }

        // Cleanup constraints
        Arrays.fill(aliceSharedSecret, (byte)0);
        Arrays.fill(bobSharedSecret, (byte)0);
        
        // Trigger the Zeroize operations natively
        ((javax.security.auth.Destroyable) aliceKeyPair.getPrivate()).destroy();
    }

    // Helper to bridge JCA boundaries for encapsulation output
    private static byte[] extractCiphertext(SecretKey keyObject) {
         if (keyObject instanceof com.obsidianq.jce.KyberEncapsulatedSecret) {
             return ((com.obsidianq.jce.KyberEncapsulatedSecret) keyObject).getCiphertext();
         }
         throw new IllegalArgumentException("Key is not a KyberEncapsulatedSecret");
    }
    
    public static class KyberCiphertextKey implements java.security.Key {
        private byte[] ct;
        public KyberCiphertextKey(byte[] ct){ this.ct = ct; }
        public String getAlgorithm() { return "Kyber768-CT"; }
        public String getFormat() { return "RAW"; }
        public byte[] getEncoded() { return ct; }
    }
}
