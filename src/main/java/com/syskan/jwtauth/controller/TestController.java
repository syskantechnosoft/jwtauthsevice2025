package com.syskan.jwtauth.controller;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
// import org.springframework.security.access.prepost.PreAuthorize; // Alternative
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.syskan.jwtauth.dto.ErrorResponse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

@Tag(name = "Test Endpoints", description = "Endpoints to test role-based access")
@RestController
@RequestMapping("/api/test")
@SecurityRequirement(name = "bearerAuth") // Applies Bearer Auth to all methods in this controller for Swagger
public class TestController {

	private ResponseEntity<String> createSuccessResponse(String message, Principal principal) {
		String username = (principal != null && principal.getName() != null) ? principal.getName() : "Unknown User";
		return ResponseEntity.ok(String.format(message, username));
	}

	@Operation(summary = "Public endpoint", security = {}, // Override controller-level security for this specific
															// endpoint
			responses = {
					@ApiResponse(responseCode = "200", description = "Success", content = @Content(mediaType = "text/plain", schema = @Schema(type = "string"))) })
	@GetMapping("/public")
	public ResponseEntity<String> publicEndpoint() {
		return ResponseEntity.ok("This is a public endpoint, accessible by anyone.");
	}

	@Operation(summary = "Customer accessible endpoint", responses = {
			@ApiResponse(responseCode = "200", description = "Success", content = @Content(mediaType = "text/plain", schema = @Schema(type = "string"))),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))) })
	@GetMapping("/customer")
	// @PreAuthorize("hasAnyRole('CUSTOMER', 'ADMIN', 'MANAGER', 'HR')")
	public ResponseEntity<String> customerEndpoint(Principal principal) {
		return createSuccessResponse("Hello Customer %s! This is for CUSTOMER, HR, MANAGER, ADMIN.", principal);
	}

	@Operation(summary = "HR accessible endpoint", responses = {
			@ApiResponse(responseCode = "200", description = "Success", content = @Content(mediaType = "text/plain", schema = @Schema(type = "string"))),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))) })
	@GetMapping("/hr")
	// @PreAuthorize("hasAnyRole('HR', 'ADMIN')")
	public ResponseEntity<String> hrEndpoint(Principal principal) {
		return createSuccessResponse("Hello HR %s! This is for HR and ADMIN.", principal);
	}

	@Operation(summary = "Manager accessible endpoint", responses = {
			@ApiResponse(responseCode = "200", description = "Success", content = @Content(mediaType = "text/plain", schema = @Schema(type = "string"))),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))) })
	@GetMapping("/manager")
	// @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN')")
	public ResponseEntity<String> managerEndpoint(Principal principal) {
		return createSuccessResponse("Hello Manager %s! This is for MANAGER and ADMIN.", principal);
	}

	@Operation(summary = "Admin accessible endpoint", responses = {
			@ApiResponse(responseCode = "200", description = "Success", content = @Content(mediaType = "text/plain", schema = @Schema(type = "string"))),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))),
			@ApiResponse(responseCode = "403", description = "Forbidden", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))) })
	@GetMapping("/admin")
	// @PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<String> adminEndpoint(Principal principal) {
		return createSuccessResponse("Hello Admin %s! This is for ADMIN only.", principal);
	}

	@Operation(summary = "Any authenticated user endpoint", responses = {
			@ApiResponse(responseCode = "200", description = "Success", content = @Content(mediaType = "text/plain", schema = @Schema(type = "string"))),
			@ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorResponse.class))) })
	@GetMapping("/any-authenticated")
	public ResponseEntity<String> anyAuthenticatedEndpoint(Principal principal) {
		return createSuccessResponse("Hello %s! This is for any authenticated user.", principal);
	}
}
