package com.syskan.jwtauth.dto;

import com.syskan.jwtauth.enums.Role;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response object containing JWT token and user details after successful authentication")
public class AuthResponse {
	@Schema(description = "JWT authentication token", example = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJST0xFX1VTRVIiLCJpYXQiOjE2Nzgz...")
	private String token;

	@Schema(description = "Username of the authenticated user", example = "testuser")
	private String username;

	@Schema(description = "Role of the authenticated user", example = "ROLE_CUSTOMER")
	private Role role;
}
