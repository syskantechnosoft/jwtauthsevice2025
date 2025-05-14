package com.syskan.jwtauth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.syskan.jwtauth.dto.AuthResponse;
import com.syskan.jwtauth.dto.ErrorResponse;
import com.syskan.jwtauth.dto.LoginRequest;
import com.syskan.jwtauth.dto.RegisterRequest;
import com.syskan.jwtauth.model.User;
import com.syskan.jwtauth.service.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

@Tag(name = "Authentication", description = "APIs for user registration and login")
@RestController
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	private AuthService authService;

	@Operation(summary = "Register a new user", responses = {
			@ApiResponse(responseCode = "201", description = "User registered successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = String.class))),
			@ApiResponse(responseCode = "400", description = "Invalid input / User already exists", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))) })
	@PostMapping("/register")
	public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
		// AuthService will throw IllegalArgumentException if user exists, handled by
		// GlobalExceptionHandler
		User registeredUser = authService.register(registerRequest);
		return ResponseEntity.status(HttpStatus.CREATED)
				.body("User registered successfully: " + registeredUser.getUsername());
	}

	@Operation(summary = "Login an existing user", responses = {
			@ApiResponse(responseCode = "200", description = "Login successful, returns JWT token", content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthResponse.class))),
			@ApiResponse(responseCode = "401", description = "Invalid credentials", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))) })
	@PostMapping("/login")
	public ResponseEntity<AuthResponse> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
		// AuthService will let Spring Security handle BadCredentialsException, handled
		// by GlobalExceptionHandler
		AuthResponse authResponse = authService.login(loginRequest);
		return ResponseEntity.ok(authResponse);
	}
}
