package org.example.lab1.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import org.example.lab1.DTO.OrderDTO;
import org.example.lab1.DTO.OrderEntryDTO;
import org.example.lab1.DatabaseIntegrationTests;
import org.example.lab1.repository.CategoryRepository;
import org.example.lab1.repository.OrderEntryRepository;
import org.example.lab1.repository.OrderRepository;
import org.example.lab1.repository.ProductRepository;
import org.example.lab1.repository.entity.category.CategoryEntity;
import org.example.lab1.repository.entity.order.OrderEntity;
import org.example.lab1.repository.entity.order.OrderEntryEntity;
import org.example.lab1.repository.entity.order.OrderEntryId;
import org.example.lab1.repository.entity.product.ProductEntity;
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

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class OrderControllerIT extends DatabaseIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private OrderEntryRepository orderEntryRepository;

    @BeforeEach
    void setUp() {
        orderEntryRepository.deleteAll();
        orderRepository.deleteAll();
        productRepository.deleteAll();
        categoryRepository.deleteAll();
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testCreateOrder() throws Exception {
        OrderDTO orderDTO = OrderDTO.builder()
                .customerName("Test Customer")
                .email("testcustomer@mail.com")
                .build();

        mockMvc.perform(post("/api/v1/orders")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(orderDTO)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.customerName").value("Test Customer"))
                .andExpect(jsonPath("$.email").value("testcustomer@mail.com"));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetOrderById() throws Exception {
        OrderEntity order = orderRepository.save(
                OrderEntity.builder()
                        .customerName("Test Customer")
                        .orderDate(LocalDateTime.now())
                        .email("testcustomer@mail.com")
                        .build()
        );

        mockMvc.perform(get("/api/v1/orders/{orderId}", order.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.customerName").value("Test Customer"))
                .andExpect(jsonPath("$.email").value("testcustomer@mail.com"));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testDeleteOrderById() throws Exception {
        OrderEntity order = orderRepository.save(
                OrderEntity.builder()
                        .customerName("Test Customer")
                        .orderDate(LocalDateTime.now())
                        .email("testcustomer@mail.com")
                        .build()
        );

        mockMvc.perform(delete("/api/v1/orders/{orderId}", order.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());

        assertFalse(orderRepository.existsById(order.getId()));
    }

}
