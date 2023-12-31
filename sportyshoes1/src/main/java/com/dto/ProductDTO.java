package com.dto;

public class ProductDTO {

	
	
	private Long id;
	private String name;
	private int categoryId;
	private double price;
	private double size;
	private String description;
	private String imageName;
	public ProductDTO() {
		super();
		
	}
	public ProductDTO(Long id, String name, int categoryId, double price, double size, String description,
			String imageName) {
		super();
		this.id = id;
		this.name = name;
		this.categoryId = categoryId;
		this.price = price;
		this.size = size;
		this.description = description;
		this.imageName = imageName;
	}
	public ProductDTO(String name, int categoryId, double price, double size, String description, String imageName) {
		super();
		this.name = name;
		this.categoryId = categoryId;
		this.price = price;
		this.size = size;
		this.description = description;
		this.imageName = imageName;
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getCategoryId() {
		return categoryId;
	}
	public void setCategoryId(int categoryId) {
		this.categoryId = categoryId;
	}
	public double getPrice() {
		return price;
	}
	public void setPrice(double price) {
		this.price = price;
	}
	public double getSize() {
		return size;
	}
	public void setSize(double size) {
		this.size = size;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public String getImageName() {
		return imageName;
	}
	public void setImageName(String imageName) {
		this.imageName = imageName;
	}
	@Override
	public String toString() {
		return "ProductDTO [id=" + id + ", name=" + name + ", categoryId=" + categoryId + ", price=" + price
				+ ", weight=" + size + ", description=" + description + ", imageName=" + imageName + "]";
	}

	
	
	
}
