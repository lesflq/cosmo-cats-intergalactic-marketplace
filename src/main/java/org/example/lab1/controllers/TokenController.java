package org.example.lab1.controllers;

import org.example.lab1.config.JWT.JwtGenerator;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;

@RestController
public class TokenController {

    private final JwtGenerator jwtGenerator;

    public TokenController(JwtGenerator jwtGenerator) {
        this.jwtGenerator = jwtGenerator;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public byte[] getJwks() throws Exception {
        return Files.readAllBytes(new ClassPathResource("static/jwks.json").getFile().toPath());
    }

    @GetMapping("/generate-token")
    public String generateToken(@RequestParam String username) {
        try {
            return jwtGenerator.generateToken(username);
        } catch (Exception e) {
            throw new RuntimeException("Error generating token", e);
        }
    }
}

