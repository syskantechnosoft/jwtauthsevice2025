package com.syskan.jwtauth.dto;

import com.syskan.jwtauth.enums.Role;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
@Schema(description = "Request object for user registration")
public class RegisterRequest {
	@NotBlank(message = "Username cannot be blank")
	@Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
	@Schema(description = "Desired username", requiredMode = Schema.RequiredMode.REQUIRED, example = "newuser")
	private String username;

	@NotBlank(message = "Email cannot be blank")
	@Email(message = "Email should be valid")
	@Schema(description = "User's email address", requiredMode = Schema.RequiredMode.REQUIRED, example = "newuser@example.com")
	private String email;

	@NotBlank(message = "Password cannot be blank")
	@Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
	@Schema(description = "User's desired password", requiredMode = Schema.RequiredMode.REQUIRED, example = "Str0ngP@ssw0rd!")
	private String password;

	@NotNull(message = "Role cannot be null")
	@Schema(description = "User's role", requiredMode = Schema.RequiredMode.REQUIRED, example = "ROLE_CUSTOMER")
	private Role role;
}
