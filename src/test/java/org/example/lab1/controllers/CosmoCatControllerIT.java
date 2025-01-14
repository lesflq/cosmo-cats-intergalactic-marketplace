package org.example.lab1.controllers;

import org.example.lab1.service.implementation.CosmoCatServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CosmoCatControllerIT {

    @MockBean
    private CosmoCatServiceImpl cosmoCatServiceImpl;

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetCosmoCats() throws Exception {
        List<String> cosmoCats = List.of("tisha", "charlik");

        when(cosmoCatServiceImpl.getCosmoCats()).thenReturn(cosmoCats);

        mockMvc.perform(get("/api/v1/cosmo-cats")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().json("[\"tisha\", \"charlik\"]"));

        verify(cosmoCatServiceImpl, times(1)).getCosmoCats();
    }
}

