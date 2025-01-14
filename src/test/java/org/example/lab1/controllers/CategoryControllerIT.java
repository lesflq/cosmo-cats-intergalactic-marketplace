package org.example.lab1.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.lab1.DTO.CategoryDTO;
import org.example.lab1.DatabaseIntegrationTests;
import org.example.lab1.repository.CategoryRepository;
import org.example.lab1.repository.entity.category.CategoryEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class CategoryControllerIT extends DatabaseIntegrationTests {


    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CategoryRepository categoryRepository;

    @BeforeEach
    void setUp() {
        categoryRepository.deleteAll();
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testCreateCategory() throws Exception {
        CategoryDTO categoryDTO = CategoryDTO.builder()
                .name("Test Category")
                .build();

        mockMvc.perform(post("/api/v1/categories")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(categoryDTO)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Test Category"));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetAllCategories() throws Exception {
        categoryRepository.saveAll(List.of(
                CategoryEntity.builder().name("Category 1").build(),
                CategoryEntity.builder().name("Category 2").build()
        ));

        mockMvc.perform(get("/api/v1/categories")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].name").value("Category 1"))
                .andExpect(jsonPath("$[1].name").value("Category 2"));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetCategoryById() throws Exception {
        // Додати категорію у базу даних
        CategoryEntity category = categoryRepository.save(
                CategoryEntity.builder().name("Test Category").build()
        );

        mockMvc.perform(get("/api/v1/categories/{id}", category.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Test Category"));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testUpdateCategory() throws Exception {
        CategoryEntity category = categoryRepository.save(
                CategoryEntity.builder().name("Old Category").build()
        );

        CategoryDTO updatedCategoryDTO = CategoryDTO.builder()
                .name("Updated Category")
                .build();

        mockMvc.perform(put("/api/v1/categories/{id}", category.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updatedCategoryDTO)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Updated Category"));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testDeleteCategory() throws Exception {
        CategoryEntity category = categoryRepository.save(
                CategoryEntity.builder().name("Test Category").build()
        );

        mockMvc.perform(delete("/api/v1/categories/{id}", category.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());

        assertFalse(categoryRepository.existsById(category.getId()));
    }
}