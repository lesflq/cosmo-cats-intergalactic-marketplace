package org.example.lab1.service;

import jakarta.persistence.EntityNotFoundException;
import org.example.lab1.DTO.ProductDTO;
import org.example.lab1.domain.product.Product;
import org.example.lab1.mappers.ProductMapper;
import org.example.lab1.repository.CategoryRepository;
import org.example.lab1.repository.ProductRepository;
import org.example.lab1.repository.entity.category.CategoryEntity;
import org.example.lab1.repository.entity.product.ProductEntity;
import org.example.lab1.service.implementation.ProductServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.test.context.support.WithMockUser;

import java.math.BigDecimal;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ProductServiceTest {

    @Mock
    private ProductRepository productRepository;

    @Mock
    private CategoryRepository categoryRepository;

    @Mock
    private ProductMapper productMapper;

    @InjectMocks
    private ProductServiceImpl productService;

    @Test
    void testCreateProduct_Success() {
        ProductDTO productDTO = ProductDTO.builder()
                .id(1L)
                .name("Product")
                .price(BigDecimal.valueOf(100.0))
                .description("Description")
                .categoryId(1L)
                .build();

        CategoryEntity categoryEntity = CategoryEntity.builder()
                .id(1L)
                .name("Category")
                .build();

        ProductEntity productEntity = ProductEntity.builder()
                .id(1L)
                .name("Product")
                .price(BigDecimal.valueOf(100.0))
                .description("Description")
                .category(categoryEntity)
                .build();

        when(categoryRepository.findById(1L)).thenReturn(Optional.of(categoryEntity));
        when(productRepository.save(any(ProductEntity.class))).thenReturn(productEntity);
        when(productMapper.toDTO(any(ProductEntity.class))).thenReturn(productDTO);

        ProductDTO result = productService.createProduct(productDTO);

        assertNotNull(result);
        assertEquals("Product", result.getName());
        assertEquals(BigDecimal.valueOf(100.0), result.getPrice());
    }

    @Test
    void testCreateProduct_CategoryNotFound() {
        ProductDTO productDTO = ProductDTO.builder()
                .id(1L)
                .name("Product")
                .price(BigDecimal.valueOf(100.0))
                .description("Description")
                .categoryId(1L)
                .build();

        when(categoryRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(EntityNotFoundException.class, () -> productService.createProduct(productDTO));
    }

    @Test
    void testGetAllProducts() {
        ProductEntity productEntity = ProductEntity.builder()
                .id(1L)
                .name("Product")
                .price(BigDecimal.valueOf(100.0))
                .description("Description")
                .category(new CategoryEntity())
                .build();

        List<ProductEntity> productEntities = Arrays.asList(productEntity);

        when(productRepository.findAll()).thenReturn(productEntities);
        when(productMapper.toProductDTOList(anyList())).thenReturn(Collections.singletonList(
                ProductDTO.builder()
                        .id(1L)
                        .name("Product")
                        .price(BigDecimal.valueOf(100.0))
                        .description("Description")
                        .categoryId(1L)
                        .build()));

        List<ProductDTO> result = productService.getAllProducts();

        assertNotNull(result);
        assertEquals(1, result.size());
    }

    @Test
    void testGetProductById_Success() {
        ProductEntity productEntity = ProductEntity.builder()
                .id(1L)
                .name("Product")
                .price(BigDecimal.valueOf(100.0))
                .description("Description")
                .category(new CategoryEntity())
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.of(productEntity));
        when(productMapper.toDTO(any(ProductEntity.class))).thenReturn(ProductDTO.builder()
                .id(1L)
                .name("Product")
                .price(BigDecimal.valueOf(100.0))
                .description("Description")
                .categoryId(1L)
                .build());

        ProductDTO result = productService.getProductById(1L);

        assertNotNull(result);
        assertEquals("Product", result.getName());
    }

    @Test
    void testGetProductById_NotFound() {
        when(productRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> productService.getProductById(1L));
    }

    @Test
    void testUpdateProduct_Success() {
        ProductDTO productDTO = ProductDTO.builder()
                .id(1L)
                .name("Updated Product")
                .price(BigDecimal.valueOf(120.0))
                .description("Updated Description")
                .categoryId(1L)
                .build();

        ProductEntity productEntity = ProductEntity.builder()
                .id(1L)
                .name("Product")
                .price(BigDecimal.valueOf(100.0))
                .description("Description")
                .category(new CategoryEntity())
                .build();

        CategoryEntity categoryEntity = CategoryEntity.builder()
                .id(1L)
                .name("Category")
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.of(productEntity));
        when(categoryRepository.findById(1L)).thenReturn(Optional.of(categoryEntity));
        when(productRepository.save(any(ProductEntity.class))).thenReturn(productEntity);
        when(productMapper.toDTO(any(ProductEntity.class))).thenReturn(ProductDTO.builder()
                .id(1L)
                .name("Updated Product")
                .price(BigDecimal.valueOf(120.0))
                .description("Updated Description")
                .categoryId(1L)
                .build());

        ProductDTO result = productService.updateProduct(1L, productDTO);

        assertNotNull(result);
        assertEquals("Updated Product", result.getName());
        assertEquals(BigDecimal.valueOf(120.0), result.getPrice());
    }

    @Test
    void testUpdateProduct_ProductNotFound() {
        ProductDTO productDTO = ProductDTO.builder()
                .id(1L)
                .name("Updated Product")
                .price(BigDecimal.valueOf(120.0))
                .description("Updated Description")
                .categoryId(1L)
                .build();

        when(productRepository.findById(1L)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> productService.updateProduct(1L, productDTO));
    }

    @Test
    void testDeleteProduct_Success() {
        when(productRepository.existsById(1L)).thenReturn(true);

        productService.deleteProduct(1L);

        verify(productRepository).deleteById(1L);
    }

}
