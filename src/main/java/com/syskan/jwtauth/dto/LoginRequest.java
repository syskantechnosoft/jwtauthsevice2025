package com.syskan.jwtauth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Request object for user login")
public class LoginRequest {
    @NotBlank(message = "Username cannot be blank")
    @Schema(description = "Username for login", requiredMode = Schema.RequiredMode.REQUIRED, example = "testuser")
    private String username;

    @NotBlank(message = "Password cannot be blank")
    @Schema(description = "Password for login", requiredMode = Schema.RequiredMode.REQUIRED, example = "password123")
    private String password;
}

