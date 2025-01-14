package org.example.lab1.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import net.bytebuddy.utility.dispatcher.JavaDispatcher;
import org.example.lab1.DTO.ProductDTO;
import org.example.lab1.DatabaseIntegrationTests;
import org.example.lab1.repository.CategoryRepository;
import org.example.lab1.repository.ProductRepository;
import org.example.lab1.repository.entity.category.CategoryEntity;
import org.example.lab1.repository.entity.product.ProductEntity;
import org.example.lab1.service.implementation.ProductServiceImpl;
import org.hibernate.dialect.Database;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.junit.jupiter.Container;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class ProductControllerIT extends DatabaseIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private CategoryRepository categoryRepository;

    @BeforeEach
    void setUp() {
        productRepository.deleteAll();
        categoryRepository.deleteAll();
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testCreateProduct() throws Exception {
        CategoryEntity category = categoryRepository.save(
                CategoryEntity.builder()
                        .name("Test Category")
                        .build()
        );

        ProductDTO productDTO = ProductDTO.builder()
                .name("Test Product Star")
                .price(BigDecimal.valueOf(100.0))
                .description("Test description")
                .categoryId(category.getId())
                .build();

        mockMvc.perform(post("/api/v1/products")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(productDTO)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Test Product Star"))
                .andExpect(jsonPath("$.price").value(100.0));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetAllProducts() throws Exception {
        CategoryEntity category = categoryRepository.save(
                CategoryEntity.builder()
                        .name("Test Category")
                        .build()
        );

        productRepository.saveAll(List.of(
                ProductEntity.builder()
                        .name("Product 1")
                        .price(BigDecimal.valueOf(50.0))
                        .description("Description 1")
                        .category(category)
                        .build(),
                ProductEntity.builder()
                        .name("Product 2")
                        .price(BigDecimal.valueOf(150.0))
                        .description("Description 2")
                        .category(category)
                        .build()
        ));

        mockMvc.perform(get("/api/v1/products")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetProductById() throws Exception {
        CategoryEntity category = categoryRepository.save(
                CategoryEntity.builder()
                        .name("Test Category")
                        .build()
        );

        ProductEntity product = productRepository.save(
                ProductEntity.builder()
                        .name("Test Product")
                        .price(BigDecimal.valueOf(100.0))
                        .description("Test Description")
                        .category(category)
                        .build()
        );

        mockMvc.perform(get("/api/v1/products/{id}", product.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Test Product"));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testUpdateProduct() throws Exception {
        CategoryEntity category = categoryRepository.save(
                CategoryEntity.builder()
                        .name("Test Category")
                        .build()
        );

        ProductEntity product = productRepository.save(
                ProductEntity.builder()
                        .name("Star Product")
                        .price(BigDecimal.valueOf(100.0))
                        .description("Test Description")
                        .category(category)
                        .build()
        );

        ProductDTO updatedProductDTO = ProductDTO.builder()
                .name("Galaxy Product")
                .price(BigDecimal.valueOf(200.0))
                .description("Updated Description")
                .categoryId(category.getId())
                .build();

        mockMvc.perform(put("/api/v1/products/{id}", product.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updatedProductDTO)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Galaxy Product"))
                .andExpect(jsonPath("$.price").value(200.0));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testDeleteProduct() throws Exception {
        CategoryEntity category = categoryRepository.save(
                CategoryEntity.builder()
                        .name("Test Category")
                        .build()
        );

        ProductEntity product = productRepository.save(
                ProductEntity.builder()
                        .name("Test Product")
                        .price(BigDecimal.valueOf(100.0))
                        .description("Test Description")
                        .category(category)
                        .build()
        );

        mockMvc.perform(delete("/api/v1/products/{id}", product.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());

        assertFalse(productRepository.existsById(product.getId()));
    }
}
