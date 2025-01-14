package org.example.lab1.controllers;

import org.example.lab1.config.GreetingProperties;
import org.example.lab1.config.GreetingProperties.CatGreeting;
import org.example.lab1.featuretoggle.service.FeatureToggleService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

@SpringBootTest
@AutoConfigureMockMvc
class GreetingControllerIT {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private GreetingProperties greetingProperties;

    @MockBean
    private FeatureToggleService featureToggleService;

    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetGreeting_WhenFeatureEnabled() throws Exception {
        CatGreeting greeting = new CatGreeting();
        greeting.setName("Cosmo");
        greeting.setMessage("Hello, Cosmo! Welcome to the space adventure.");
        when(greetingProperties.getGreetings()).thenReturn(Map.of("Cosmo", greeting));
        when(featureToggleService.check("cosmoCats")).thenReturn(true);

        mockMvc.perform(get("/api/v1/greetings/Cosmo")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, Cosmo! Welcome to the space adventure."));
    }

    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetGreeting_WhenFeatureDisabled() throws Exception {
        when(featureToggleService.check("cosmoCats")).thenReturn(false);

        mockMvc.perform(get("/api/v1/greetings/Cosmo")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }
}

