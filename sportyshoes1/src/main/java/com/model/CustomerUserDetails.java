package com.model;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public class CustomerUserDetails extends User implements UserDetails {
	

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public CustomerUserDetails(Integer id, @NotEmpty String firstName, String lastName,
			@NotEmpty @Email(message = "{errors.invalid_email}") String email, @NotEmpty String password,
			List<Role> roles) {
		super(id, firstName, lastName, email, password, roles);
		
	}

	public CustomerUserDetails(@NotEmpty String firstName, String lastName,
			@NotEmpty @Email(message = "{errors.invalid_email}") String email, @NotEmpty String password,
			List<Role> roles) {
		super(firstName, lastName, email, password, roles);
		
	}

	public CustomerUserDetails(User user) {
		super(user);
		
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		List<GrantedAuthority> authorityList = new ArrayList<>();
		super.getRoles().forEach(role -> {
			authorityList.add(new SimpleGrantedAuthority(role.getName()));
		}
				);
		return authorityList;
	}

	@Override
	public String getUsername() {
		return super.getEmail();
	}
	@Override
	public String getPassword() {
		return super.getPassword();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	
}
