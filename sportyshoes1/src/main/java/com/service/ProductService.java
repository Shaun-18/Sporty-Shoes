package com.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.model.Product;
import com.repository.ProductRepository;

@Service
public class ProductService {

	
	@Autowired
	ProductRepository productRepository;
	
	
	public List<Product> getAllProduct(){return productRepository.findAll();}
	
	public void addProduct(Product product)
	{
		productRepository.save(product);
	}
	
	public void removeProductById(Long id)
	{
		productRepository.deleteById(id);
	}
	
	public Product getProductById(Long id)
	{
		return productRepository.findById(id).get();
	}
	
	public List<Product> getAllProductsByCategoryId(int id)
	{
		return productRepository.findAllByCategory_Id(id);
	}
	
	
	
	
	
	}
