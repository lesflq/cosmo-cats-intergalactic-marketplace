package org.example.lab1.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
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
import org.example.lab1.service.OrderEntryService;
import org.example.lab1.service.implementation.OrderEntryServiceImpl;
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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class OrderEntryControllerIT extends DatabaseIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private OrderEntryRepository orderEntryRepository;

    @Autowired
    private CategoryRepository categoryRepository;

    @BeforeEach
    void setUp() {
        orderEntryRepository.deleteAll();
        orderRepository.deleteAll();
        productRepository.deleteAll();
        categoryRepository.deleteAll();
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testAddProductToOrder() throws Exception {
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

        OrderEntity order = orderRepository.save(
                OrderEntity.builder()
                        .customerName("Test Customer")
                        .orderDate(LocalDateTime.now())
                        .email("testcustomer@mail.com")
                        .build()
        );

        OrderEntryDTO orderEntryDTO = OrderEntryDTO.builder()
                .productId(product.getId())
                .amount(3)
                .build();

        mockMvc.perform(post("/api/v1/order/entry/{orderId}/products", order.getId())
                        .with(csrf())
                        .param("productId", product.getId().toString())
                        .param("amount", "3")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(orderEntryDTO)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.productId").value(product.getId()))
                .andExpect(jsonPath("$.amount").value(3));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testRemoveProductFromOrder() throws Exception {
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

        OrderEntity order = orderRepository.save(
                OrderEntity.builder()
                        .customerName("Test Customer")
                        .orderDate(LocalDateTime.now())
                        .email("testcustomer@mail.com")
                        .build()
        );

        OrderEntryId orderEntryId = new OrderEntryId(order.getId(), product.getId());

        OrderEntryEntity orderEntry = OrderEntryEntity.builder()
                .id(orderEntryId) // Встановлюємо складений ключ
                .order(order)
                .product(product)
                .amount(3)
                .build();

        mockMvc.perform(delete("/api/v1/order/entry/{orderId}/products/{productId}", order.getId(), product.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNoContent());

        assertFalse(orderEntryRepository.existsById(orderEntry.getId()));
    }
    @Test
    @WithMockUser(username = "test_user", roles = {"USER"})
    void testGetOrderEntries() throws Exception {
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

        OrderEntity order = orderRepository.save(
                OrderEntity.builder()
                        .customerName("Test Customer")
                        .orderDate(LocalDateTime.now())
                        .email("testcustomer@mail.com")
                        .build()
        );

        OrderEntryId orderEntryId = new OrderEntryId(order.getId(), product.getId());

        OrderEntryEntity orderEntry = OrderEntryEntity.builder()
                .id(orderEntryId) // Встановлюємо складений ключ
                .order(order)
                .product(product)
                .amount(3)
                .build();
        orderEntryRepository.save(orderEntry);


        mockMvc.perform(get("/api/v1/order/entry/{orderId}/products", order.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));
    }
}
