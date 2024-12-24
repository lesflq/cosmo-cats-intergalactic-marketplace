package org.example.lab1.config.noauth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Profile("no-auth")
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(NoAuthProperties.class)
public class NoAuthSecurityConfig {

    @Bean
    @Order(Integer.MIN_VALUE)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.warn("All requests are permitted in no-auth profile");
        http
                .csrf(CsrfConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    @Order(Integer.MIN_VALUE)
    public WebSecurityCustomizer webSecurityCustomizer() {
        return WebSecurity::ignoring;
    }

    @Bean
    public OncePerRequestFilter authenticationFilter(NoAuthProperties noAuthProperties) {
        return new AuthenticationFilter(noAuthProperties.getClaims());
    }

    private class AuthenticationFilter extends OncePerRequestFilter {

        private final Map<String, Object> claims;

        public AuthenticationFilter(Map<String, Object> claims) {
            this.claims = claims;
        }

        @Override
        protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                        @NonNull  FilterChain filterChain) throws ServletException, IOException {
            JwtAuthenticationToken jwtToken = new JwtAuthenticationToken(Jwt.withTokenValue("tokenVal")
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plus(Duration.ofMinutes(3)))
                    .header("alg", "RS256")
                    .header("kid", "c9e57581-a7c2-4af1-ba80-fa9ddd5a0216")
                    .claims((headers) -> headers.putAll(claims))
                    .build());
            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(jwtToken);
            filterChain.doFilter(request, response);
        }
    }

}