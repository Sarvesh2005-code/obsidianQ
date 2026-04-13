package com.obsidianq.util;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * The zero-dependency architecture enabler.
 * This class mathematically maps the OS extension and architecture,
 * locates the embedded Rust dynamic library within our compiled JAR's resources,
 * and seamlessly extracts it to a volatile temporary directory for JNI loading.
 * This ensures ObsidianQ functions as a singular, plug-and-play `.jar`.
 */
public class NativeExtractor {
    
    public static void loadLibrary() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String libraryName;

            if (os.contains("win")) {
                libraryName = "obsidian_core.dll";
            } else if (os.contains("mac")) {
                libraryName = "libobsidian_core.dylib";
            } else {
                libraryName = "libobsidian_core.so";
            }

            // Target the resource embedded by Maven 
            String resourcePath = "/natives/" + libraryName;
            
            try (InputStream in = NativeExtractor.class.getResourceAsStream(resourcePath)) {
                if (in == null) {
                    throw new RuntimeException("Fatal: Missing embedded cryptography core: " + resourcePath);
                }
                
                // Extract to secure OS temporary sector
                Path tempFile = Files.createTempFile("obsidian_core_", ".lib");
                tempFile.toFile().deleteOnExit(); // Ensure volatile cleanup
                
                Files.copy(in, tempFile, StandardCopyOption.REPLACE_EXISTING);
                
                // Bridge initializing directly from temp file
                System.load(tempFile.toAbsolutePath().toString());
            }
        } catch (Exception e) {
            throw new RuntimeException("ObsidianQ Zero-Dependency initialization failed.", e);
        }
    }
}
