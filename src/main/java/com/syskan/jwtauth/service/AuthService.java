package com.syskan.jwtauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.syskan.jwtauth.dto.AuthResponse;
import com.syskan.jwtauth.dto.LoginRequest;
import com.syskan.jwtauth.dto.RegisterRequest;
import com.syskan.jwtauth.model.User;
import com.syskan.jwtauth.repo.UserRepository;
import com.syskan.jwtauth.util.JwtUtil;

@Service
public class AuthService {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private AuthenticationManager authenticationManager; // Injected via AppConfig

	@Transactional
	public User register(RegisterRequest registerRequest) {
		if (userRepository.existsByUsername(registerRequest.getUsername())) {
			throw new IllegalArgumentException("Error: Username is already taken!");
		}
		if (userRepository.existsByEmail(registerRequest.getEmail())) {
			throw new IllegalArgumentException("Error: Email is already in use!");
		}

		User user = User.builder().username(registerRequest.getUsername()).email(registerRequest.getEmail())
				.password(passwordEncoder.encode(registerRequest.getPassword())).role(registerRequest.getRole())
				.build();
		return userRepository.save(user);
	}

	public AuthResponse login(LoginRequest loginRequest) {
		// AuthenticationManager will use UserDetailsServiceImpl and PasswordEncoder
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		// The principal is the UserDetails object returned by UserDetailsServiceImpl
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		String jwt = jwtUtil.generateToken(userDetails);

		// We need to ensure userDetails is our User entity to get the role directly for
		// the response
		User user = userRepository.findByUsername(userDetails.getUsername()).orElseThrow(
				() -> new IllegalStateException("User not found after successful authentication - data inconsistency"));

		return new AuthResponse(jwt, userDetails.getUsername(), user.getRole());
	}
}
