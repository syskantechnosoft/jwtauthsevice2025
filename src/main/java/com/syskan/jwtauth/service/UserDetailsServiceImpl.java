package com.syskan.jwtauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.syskan.jwtauth.model.User;
import com.syskan.jwtauth.repo.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

	@Override
	@Transactional(readOnly = true) // Good practice for read operations
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepository.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
		// Spring Security's DaoAuthenticationProvider will use the UserDetails returned
		// here
		// (including its getAuthorities() and getPassword()) to authenticate.
		return user; // Our User entity implements UserDetails
	}
}
