package com.syskan.jwtauth.dto;

import java.time.LocalDateTime;
import java.util.Map;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Standard error response format")
public class ErrorResponse {
    @Schema(description = "HTTP status code", example = "400")
    private int statusCode;

    @Schema(description = "Error message", example = "Validation Failed")
    private String message;

    @Schema(description = "Timestamp of when the error occurred", example = "2023-03-15T10:30:00")
    private LocalDateTime timestamp;

    @Schema(description = "Path where the error occurred", example = "/api/auth/register")
    private String path;

    @Schema(description = "Map of validation errors, if applicable (field -> error message)", 
            example = "{\"username\": \"Username cannot be blank\", \"email\": \"Email should be valid\"}",
            nullable = true)
    private Map<String, String> validationErrors;

    public ErrorResponse(int statusCode, String message, String path) {
        this.statusCode = statusCode;
        this.message = message;
        this.path = path;
        this.timestamp = LocalDateTime.now();
    }
}
