package org.example.lab1.controllers;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/profile")
public class ProfileController {
    @GetMapping
    public String getUserProfile(OAuth2AuthenticationToken authentication) {
        return authentication.getPrincipal().getAttributes().toString();
    }
}
