package org.example.lab1.config.JWT;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {

    @Bean
    public JwtGenerator jwtGenerator() throws Exception {
        return new JwtGenerator("private_key.pem");
    }
}

