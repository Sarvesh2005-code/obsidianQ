package com.obsidianq;

import java.nio.ByteBuffer;

public class ObsidianNativeBridge {
    
    // Load the native Rust dynamic library at runtime
    static {
        System.loadLibrary("obsidian_core"); 
    }

    /**
     * Fills the provided direct ByteBuffer with a newly generated Kyber shared secret.
     * By using a direct ByteBuffer, the JVM Garbage Collector is entirely bypassed.
     * The OS memory is mapped directly to our Rust FFI boundary, preventing ghost copies
     * of the AES key from existing in managed heap memory.
     *
     * @param buffer A DirectByteBuffer (off-heap memory) allocated by the caller.
     * @param capacity The size of the expected buffer in bytes.
     * @return 0 on success, error code otherwise.
     */
    public static native int generateKyberSecret(ByteBuffer buffer, int capacity);
    
    /**
     * Architectural Demonstration
     */
    public static void secureMemoryDemo() {
        // Allocate 32 bytes strictly OFF the Java managed heap
        // This is the absolute memory safety requirement mapped to code.
        ByteBuffer secureBuffer = ByteBuffer.allocateDirect(32);
        
        int result = generateKyberSecret(secureBuffer, 32);
        
        if (result == 0) {
            // Secret now safely rests in off-heap memory awaiting cipher initialization.
            System.out.println("Secure secret loaded directly from Rust into off-heap memory.");
        }
    }
}
