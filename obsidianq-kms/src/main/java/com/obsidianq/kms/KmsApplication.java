package com.obsidianq.kms;

import com.obsidianq.jce.ObsidianQProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class KmsApplication {

    public static void main(String[] args) {
        // Register the ObsidianQ Quantum-Safe Provider
        Security.addProvider(new ObsidianQProvider());
        
        SpringApplication.run(KmsApplication.class, args);
    }
}
