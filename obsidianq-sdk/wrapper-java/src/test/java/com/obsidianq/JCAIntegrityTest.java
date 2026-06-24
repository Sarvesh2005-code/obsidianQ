package com.obsidianq;

import com.obsidianq.jce.ObsidianQProvider;
import com.obsidianq.jce.KyberParameterSpec;

import javax.crypto.KEM;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Arrays;

/**
 * Comprehensive V&V Integrity Test for ObsidianQ.
 * 
 * Tests both the modern Java 21 KEM API and the legacy JCA interface
 * to validate full quantum-safe key encapsulation round-trip integrity.
 */
public class JCAIntegrityTest {

    public static void main(String[] args) throws Exception {
        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║     ObsidianQ V&V Integrity Test Suite          ║");
        System.out.println("║     NIST FIPS 203 · ML-KEM-768                  ║");
        System.out.println("╚══════════════════════════════════════════════════╝");
        System.out.println();

        // Install the Provider globally into the JVM
        Security.addProvider(new ObsidianQProvider());

        boolean allPassed = true;
        allPassed &= testJava21KemApi();
        allPassed &= testLegacyJcaApi();
        allPassed &= testMultipleRoundTrips();
        allPassed &= testAsn1Encoding();

        System.out.println();
        if (allPassed) {
            System.out.println("═══════════════════════════════════════════════");
            System.out.println("  ✅ ALL TESTS PASSED — Quantum Safety Verified");
            System.out.println("═══════════════════════════════════════════════");
        } else {
            System.err.println("  ❌ SOME TESTS FAILED — Review output above");
            System.exit(1);
        }
    }

    // =========================================================================
    // Test 1: Java 21 javax.crypto.KEM API
    // =========================================================================
    private static boolean testJava21KemApi() {
        System.out.println("── Test 1: Java 21 KEM API (javax.crypto.KEM) ──");
        try {
            // Generate keypair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber768", "ObsidianQ");
            KeyPair kp = kpg.generateKeyPair();
            System.out.println("   [+] KeyPair generated (pk=" + kp.getPublic().getEncoded().length + "B, sk=" + kp.getPrivate().getEncoded().length + "B)");

            // Encapsulate using Java 21 KEM API
            KEM kem = KEM.getInstance("ML-KEM-768", "ObsidianQ");
            KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());
            KEM.Encapsulated encapsulated = enc.encapsulate();

            SecretKey bobSecret = encapsulated.key();
            byte[] ciphertext = encapsulated.encapsulation();
            System.out.println("   [+] Encapsulated (ct=" + ciphertext.length + "B, ss=" + bobSecret.getEncoded().length + "B)");

            // Decapsulate
            KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate());
            SecretKey aliceSecret = dec.decapsulate(ciphertext);
            System.out.println("   [+] Decapsulated (ss=" + aliceSecret.getEncoded().length + "B)");

            // Verify
            boolean match = Arrays.equals(bobSecret.getEncoded(), aliceSecret.getEncoded());
            if (match) {
                System.out.println("   [✅] PASS — Shared secrets match via KEM API");
            } else {
                System.err.println("   [❌] FAIL — Shared secrets DO NOT match");
            }

            // Cleanup
            Arrays.fill(bobSecret.getEncoded(), (byte) 0);
            Arrays.fill(aliceSecret.getEncoded(), (byte) 0);

            return match;
        } catch (Exception e) {
            System.err.println("   [❌] FAIL — Exception: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // =========================================================================
    // Test 2: Legacy JCA API (Java 8+ compatible)
    // =========================================================================
    private static boolean testLegacyJcaApi() {
        System.out.println();
        System.out.println("── Test 2: Legacy JCA API (KeyGenerator + KeyAgreement) ──");
        try {
            // Generate keypair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber768", ObsidianQProvider.PROVIDER_NAME);
            KeyPair aliceKeyPair = kpg.generateKeyPair();
            System.out.println("   [+] KeyPair generated");

            // Encapsulate via KeyGenerator
            KeyGenerator encapGen = KeyGenerator.getInstance("Kyber768", ObsidianQProvider.PROVIDER_NAME);
            encapGen.init(new KyberParameterSpec(aliceKeyPair.getPublic()));
            SecretKey bobCipherOutput = encapGen.generateKey();

            byte[] ciphertextToTransmit = extractCiphertext(bobCipherOutput);
            byte[] bobSharedSecret = bobCipherOutput.getEncoded();
            System.out.println("   [+] Encapsulated via KeyGenerator");

            // Decapsulate via KeyAgreement
            KeyAgreement decapAgreement = KeyAgreement.getInstance("Kyber768", ObsidianQProvider.PROVIDER_NAME);
            decapAgreement.init(aliceKeyPair.getPrivate());
            decapAgreement.doPhase(new KyberCiphertextKey(ciphertextToTransmit), true);
            byte[] aliceSharedSecret = decapAgreement.generateSecret();
            System.out.println("   [+] Decapsulated via KeyAgreement");

            boolean match = Arrays.equals(aliceSharedSecret, bobSharedSecret);
            if (match) {
                System.out.println("   [✅] PASS — Shared secrets match via Legacy API");
            } else {
                System.err.println("   [❌] FAIL — Shared secrets DO NOT match");
            }

            Arrays.fill(aliceSharedSecret, (byte) 0);
            Arrays.fill(bobSharedSecret, (byte) 0);

            return match;
        } catch (Exception e) {
            System.err.println("   [❌] FAIL — Exception: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // =========================================================================
    // Test 3: Multiple round-trips (stress test)
    // =========================================================================
    private static boolean testMultipleRoundTrips() {
        System.out.println();
        System.out.println("── Test 3: Stress Test (100 round-trips) ──");
        try {
            int rounds = 100;
            int passed = 0;
            long startTime = System.nanoTime();

            for (int i = 0; i < rounds; i++) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber768", "ObsidianQ");
                KeyPair kp = kpg.generateKeyPair();

                KEM kem = KEM.getInstance("ML-KEM-768", "ObsidianQ");
                KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());
                KEM.Encapsulated encapsulated = enc.encapsulate();

                KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate());
                SecretKey recovered = dec.decapsulate(encapsulated.encapsulation());

                if (Arrays.equals(encapsulated.key().getEncoded(), recovered.getEncoded())) {
                    passed++;
                }
            }

            long elapsed = (System.nanoTime() - startTime) / 1_000_000;
            double perOp = (double) elapsed / rounds;

            System.out.println("   [+] " + passed + "/" + rounds + " round-trips passed in " + elapsed + "ms");
            System.out.println("   [+] Average: " + String.format("%.2f", perOp) + "ms per full KEM cycle");

            boolean allPassed = (passed == rounds);
            if (allPassed) {
                System.out.println("   [✅] PASS — All round-trips verified");
            } else {
                System.err.println("   [❌] FAIL — " + (rounds - passed) + " round-trips failed");
            }
            return allPassed;
        } catch (Exception e) {
            System.err.println("   [❌] FAIL — Exception: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // =========================================================================
    // Test 4: ASN.1 Structural Validation
    // =========================================================================
    private static boolean testAsn1Encoding() {
        System.out.println();
        System.out.println("── Test 4: ASN.1 Structural Validation ──");
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber768", "ObsidianQ");
            KeyPair kp = kpg.generateKeyPair();

            byte[] pkEncoded = kp.getPublic().getEncoded();
            byte[] skEncoded = kp.getPrivate().getEncoded();

            // Verify X.509 format starts with SEQUENCE tag (0x30)
            if (pkEncoded == null || pkEncoded[0] != 0x30) {
                System.err.println("   [❌] FAIL — Public key does not start with ASN.1 SEQUENCE tag");
                return false;
            }

            // Verify PKCS#8 format starts with SEQUENCE tag (0x30)
            if (skEncoded == null || skEncoded[0] != 0x30) {
                System.err.println("   [❌] FAIL — Private key does not start with ASN.1 SEQUENCE tag");
                return false;
            }

            // Extract using ASN1Util
            byte[] rawPk = com.obsidianq.jce.util.ASN1Util.unwrapX509PublicKey(pkEncoded);
            byte[] rawSk = com.obsidianq.jce.util.ASN1Util.unwrapPKCS8PrivateKey(skEncoded);

            if (rawPk.length != 1184) {
                System.err.println("   [❌] FAIL — Raw PK length is " + rawPk.length + ", expected 1184");
                return false;
            }

            if (rawSk.length != 2400) {
                System.err.println("   [❌] FAIL — Raw SK length is " + rawSk.length + ", expected 2400");
                return false;
            }

            // Use the raw bytes with KEMSpi directly to verify they are valid
            com.obsidianq.jce.KyberPublicKey kpk = new com.obsidianq.jce.KyberPublicKey(java.nio.ByteBuffer.wrap(rawPk));
            com.obsidianq.jce.KyberPrivateKey ksk = new com.obsidianq.jce.KyberPrivateKey(java.nio.ByteBuffer.wrap(rawSk));

            KEM kem = KEM.getInstance("ML-KEM-768", "ObsidianQ");
            KEM.Encapsulator enc = kem.newEncapsulator(kpk);
            KEM.Encapsulated encapsulated = enc.encapsulate();

            KEM.Decapsulator dec = kem.newDecapsulator(ksk);
            SecretKey recovered = dec.decapsulate(encapsulated.encapsulation());

            if (!Arrays.equals(encapsulated.key().getEncoded(), recovered.getEncoded())) {
                System.err.println("   [❌] FAIL — Reconstructed raw keys failed KEM round-trip");
                return false;
            }

            System.out.println("   [+] ASN.1 encoding sizes: X.509=" + pkEncoded.length + "B, PKCS#8=" + skEncoded.length + "B");
            System.out.println("   [+] Successfully unwrapped to raw sizes: pk=" + rawPk.length + "B, sk=" + rawSk.length + "B");
            System.out.println("   [✅] PASS — ASN.1 X.509 and PKCS#8 encoding validated");
            return true;

        } catch (Exception e) {
            System.err.println("   [❌] FAIL — Exception: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] extractCiphertext(SecretKey keyObject) {
        if (keyObject instanceof com.obsidianq.jce.KyberEncapsulatedSecret) {
            return ((com.obsidianq.jce.KyberEncapsulatedSecret) keyObject).getCiphertext();
        }
        throw new IllegalArgumentException("Key is not a KyberEncapsulatedSecret");
    }
    
    public static class KyberCiphertextKey implements java.security.Key {
        private final byte[] ct;
        public KyberCiphertextKey(byte[] ct) { this.ct = ct; }
        public String getAlgorithm() { return "Kyber768-CT"; }
        public String getFormat() { return "RAW"; }
        public byte[] getEncoded() { return ct; }
    }
}
