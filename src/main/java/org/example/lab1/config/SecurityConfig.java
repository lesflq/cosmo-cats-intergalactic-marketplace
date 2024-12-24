package org.example.lab1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

@Configuration
public class SecurityConfig {
    @Bean
    @Order(1) // Перший пріоритет для JWT аутентифікації
    public SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/v1/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/v1/**").permitAll() // Доступ для перегляду
                        .requestMatchers(HttpMethod.POST, "/api/v1/products/**").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/v1/products/**").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/products/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/v1/order/entry/products").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/order/entry/products/{id}").authenticated()
                        .anyRequest().denyAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwkSetUri("http://localhost:8080/.well-known/jwks.json"))
                );
        return http.build();
    }
    @Bean
    @Order(2) // Другий пріоритет для GitHub аутентифікації
    public SecurityFilterChain githubSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/v1/**").permitAll() // Доступ для перегляду
                        .requestMatchers(HttpMethod.POST, "/api/v1/categories/**").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/v1/categories/**").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/categories/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/v1/orders").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/orders").authenticated()
                        .anyRequest().denyAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/oauth2/authorization/github")
                        .successHandler(new SavedRequestAwareAuthenticationSuccessHandler())
                );
        return http.build();
    }

}

