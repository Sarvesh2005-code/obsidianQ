package com.obsidianq.jce.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Zero-dependency ASN.1 DER encoder for ML-KEM-768 key structures.
 *
 * Produces standards-compliant X.509 SubjectPublicKeyInfo and PKCS#8
 * PrivateKeyInfo wrappers around raw ML-KEM key material, enabling
 * interoperability with Java KeyStores, TLS stacks, and any JCA consumer
 * that expects {@code Key.getEncoded()} to return a well-formed ASN.1 blob.
 *
 * <p>The NIST CSOR OID for ML-KEM-768 is {@code 2.16.840.1.101.3.4.4.2}
 * (FIPS 203, final assignment).</p>
 *
 * <h3>X.509 SubjectPublicKeyInfo layout (RFC 5280 §4.1):</h3>
 * <pre>
 * SEQUENCE {
 *   SEQUENCE {                       -- AlgorithmIdentifier
 *     OID 2.16.840.1.101.3.4.4.2     -- ML-KEM-768
 *   }
 *   BIT STRING {                     -- subjectPublicKey
 *     0x00                           -- zero unused-bits prefix
 *     &lt;raw public key bytes&gt;
 *   }
 * }
 * </pre>
 *
 * <h3>PKCS#8 PrivateKeyInfo layout (RFC 5958 §2):</h3>
 * <pre>
 * SEQUENCE {
 *   INTEGER 0                        -- version
 *   SEQUENCE {                       -- AlgorithmIdentifier
 *     OID 2.16.840.1.101.3.4.4.2     -- ML-KEM-768
 *   }
 *   OCTET STRING {                   -- privateKey
 *     &lt;raw private key bytes&gt;
 *   }
 * }
 * </pre>
 */
public final class ASN1Util {

    // ── ASN.1 tag constants ─────────────────────────────────────────────
    private static final byte TAG_SEQUENCE   = 0x30;
    private static final byte TAG_INTEGER    = 0x02;
    private static final byte TAG_BIT_STRING = 0x03;
    private static final byte TAG_OCTET_STRING = 0x04;
    private static final byte TAG_OID        = 0x06;

    /**
     * NIST CSOR OID for ML-KEM-768: 2.16.840.1.101.3.4.4.2
     *
     * Encoding breakdown:
     * <ul>
     *   <li>2.16  → 2×40 + 16 = 96 = 0x60</li>
     *   <li>840   → 0x86 0x48  (base-128 multi-byte)</li>
     *   <li>1     → 0x01</li>
     *   <li>101   → 0x65</li>
     *   <li>3     → 0x03</li>
     *   <li>4     → 0x04</li>
     *   <li>4     → 0x04</li>
     *   <li>2     → 0x02</li>
     * </ul>
     */
    private static final byte[] ML_KEM_768_OID = {
        0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02
    };

    private ASN1Util() { /* utility class */ }

    // ── Public API ──────────────────────────────────────────────────────

    /**
     * Wraps raw ML-KEM-768 public key bytes in an X.509 SubjectPublicKeyInfo
     * DER structure.
     *
     * @param rawPublicKey the raw 1184-byte ML-KEM-768 public key
     * @return DER-encoded SubjectPublicKeyInfo
     */
    public static byte[] wrapX509PublicKey(byte[] rawPublicKey) {
        try {
            // AlgorithmIdentifier ::= SEQUENCE { OID }
            byte[] algorithmIdentifier = derSequence(derOid(ML_KEM_768_OID));

            // BIT STRING wrapping: 1 byte unused-bits prefix (0x00) + raw key
            byte[] bitStringContent = new byte[1 + rawPublicKey.length];
            bitStringContent[0] = 0x00; // zero unused bits
            System.arraycopy(rawPublicKey, 0, bitStringContent, 1, rawPublicKey.length);
            byte[] bitString = derTagLengthValue(TAG_BIT_STRING, bitStringContent);

            // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
            return derSequence(concat(algorithmIdentifier, bitString));
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode X.509 SubjectPublicKeyInfo", e);
        }
    }

    /**
     * Wraps raw ML-KEM-768 private key bytes in a PKCS#8 PrivateKeyInfo
     * DER structure.
     *
     * @param rawPrivateKey the raw 2400-byte ML-KEM-768 private key
     * @return DER-encoded PrivateKeyInfo
     */
    public static byte[] wrapPKCS8PrivateKey(byte[] rawPrivateKey) {
        try {
            // version INTEGER ::= 0
            byte[] version = derTagLengthValue(TAG_INTEGER, new byte[] { 0x00 });

            // AlgorithmIdentifier ::= SEQUENCE { OID }
            byte[] algorithmIdentifier = derSequence(derOid(ML_KEM_768_OID));

            // privateKey OCTET STRING
            byte[] privateKeyOctetString = derTagLengthValue(TAG_OCTET_STRING, rawPrivateKey);

            // PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier, privateKey }
            return derSequence(concat(version, algorithmIdentifier, privateKeyOctetString));
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode PKCS#8 PrivateKeyInfo", e);
        }
    }

    /**
     * Extracts the raw public key bytes from an X.509 SubjectPublicKeyInfo
     * DER structure that uses the ML-KEM-768 OID.
     *
     * @param encoded the DER-encoded SubjectPublicKeyInfo
     * @return the raw public key bytes
     * @throws IllegalArgumentException if the structure is invalid
     */
    public static byte[] unwrapX509PublicKey(byte[] encoded) {
        // Outer SEQUENCE
        int[] outerSeq = expectTag(encoded, 0, TAG_SEQUENCE);
        int contentStart = outerSeq[0];
        int contentEnd   = outerSeq[1];

        // AlgorithmIdentifier SEQUENCE (skip over it)
        int[] algIdSeq = expectTag(encoded, contentStart, TAG_SEQUENCE);
        int afterAlgId = algIdSeq[1];

        // BIT STRING
        int[] bitString = expectTag(encoded, afterAlgId, TAG_BIT_STRING);
        int bsContentStart = bitString[0];
        int bsContentEnd   = bitString[1];

        // First byte of BIT STRING content is the unused-bits count (must be 0)
        if (encoded[bsContentStart] != 0x00) {
            throw new IllegalArgumentException(
                "BIT STRING has non-zero unused bits: " + encoded[bsContentStart]);
        }

        int keyLen = bsContentEnd - bsContentStart - 1;
        byte[] raw = new byte[keyLen];
        System.arraycopy(encoded, bsContentStart + 1, raw, 0, keyLen);
        return raw;
    }

    /**
     * Extracts the raw private key bytes from a PKCS#8 PrivateKeyInfo
     * DER structure that uses the ML-KEM-768 OID.
     *
     * @param encoded the DER-encoded PrivateKeyInfo
     * @return the raw private key bytes
     * @throws IllegalArgumentException if the structure is invalid
     */
    public static byte[] unwrapPKCS8PrivateKey(byte[] encoded) {
        // Outer SEQUENCE
        int[] outerSeq = expectTag(encoded, 0, TAG_SEQUENCE);
        int contentStart = outerSeq[0];

        // version INTEGER (skip)
        int[] versionInt = expectTag(encoded, contentStart, TAG_INTEGER);
        int afterVersion = versionInt[1];

        // AlgorithmIdentifier SEQUENCE (skip)
        int[] algIdSeq = expectTag(encoded, afterVersion, TAG_SEQUENCE);
        int afterAlgId = algIdSeq[1];

        // OCTET STRING containing the raw private key
        int[] octetString = expectTag(encoded, afterAlgId, TAG_OCTET_STRING);
        int osContentStart = octetString[0];
        int osContentEnd   = octetString[1];

        int keyLen = osContentEnd - osContentStart;
        byte[] raw = new byte[keyLen];
        System.arraycopy(encoded, osContentStart, raw, 0, keyLen);
        return raw;
    }

    /**
     * Returns the DER-encoded OID bytes for ML-KEM-768.
     * Useful for validation and OID comparison.
     */
    public static byte[] getMlKem768Oid() {
        return ML_KEM_768_OID.clone();
    }

    // ── DER primitive builders ──────────────────────────────────────────

    /**
     * Wraps content bytes into a SEQUENCE TLV.
     */
    private static byte[] derSequence(byte[] content) throws IOException {
        return derTagLengthValue(TAG_SEQUENCE, content);
    }

    /**
     * Encodes an OID value into a full TLV (Tag + Length + Value).
     */
    private static byte[] derOid(byte[] oidValue) throws IOException {
        return derTagLengthValue(TAG_OID, oidValue);
    }

    /**
     * Constructs a DER Tag-Length-Value triple.
     * Supports definite-length encoding up to 2^31 bytes.
     */
    private static byte[] derTagLengthValue(byte tag, byte[] value) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(2 + value.length);
        out.write(tag);
        writeLength(out, value.length);
        out.write(value);
        return out.toByteArray();
    }

    /**
     * Writes a DER definite-length encoding.
     *
     * <ul>
     *   <li>Short form (0–127): single byte</li>
     *   <li>Long form (128+): 0x80 | n followed by n bytes of big-endian length</li>
     * </ul>
     */
    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            out.write(length);
        } else if (length < 256) {
            out.write(0x81);
            out.write(length);
        } else if (length < 65536) {
            out.write(0x82);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        } else {
            // ML-KEM keys are at most ~2400 bytes; this branch is defensive.
            out.write(0x83);
            out.write((length >> 16) & 0xFF);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }

    /**
     * Concatenates two byte arrays.
     */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Concatenates three byte arrays.
     */
    private static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] result = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        System.arraycopy(c, 0, result, a.length + b.length, c.length);
        return result;
    }

    // ── DER parser helpers ──────────────────────────────────────────────

    /**
     * Reads and validates a TLV at the given offset.
     *
     * @param data   the full DER byte array
     * @param offset position of the expected tag
     * @param expectedTag the ASN.1 tag to expect
     * @return int[2] where [0] = content start, [1] = content end (exclusive)
     * @throws IllegalArgumentException on tag mismatch or malformed length
     */
    private static int[] expectTag(byte[] data, int offset, byte expectedTag) {
        if (offset >= data.length) {
            throw new IllegalArgumentException(
                "Unexpected end of data at offset " + offset);
        }
        if (data[offset] != expectedTag) {
            throw new IllegalArgumentException(
                String.format("Expected tag 0x%02X at offset %d, got 0x%02X",
                    expectedTag & 0xFF, offset, data[offset] & 0xFF));
        }

        offset++; // skip tag

        // Parse length
        int lengthByte = data[offset] & 0xFF;
        offset++;
        int contentLength;
        if (lengthByte < 128) {
            contentLength = lengthByte;
        } else {
            int numLenBytes = lengthByte & 0x7F;
            contentLength = 0;
            for (int i = 0; i < numLenBytes; i++) {
                contentLength = (contentLength << 8) | (data[offset] & 0xFF);
                offset++;
            }
        }

        return new int[] { offset, offset + contentLength };
    }
}
