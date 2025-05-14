package com.syskan.jwtauth.exception;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import com.syskan.jwtauth.dto.ErrorResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(MethodArgumentNotValidException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public ErrorResponse handleValidationExceptions(MethodArgumentNotValidException ex, WebRequest request) {
		Map<String, String> errors = new HashMap<>();
		ex.getBindingResult().getAllErrors().forEach((error) -> {
			String fieldName = ((FieldError) error).getField();
			String errorMessage = error.getDefaultMessage();
			errors.put(fieldName, errorMessage);
		});
		ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST.value(), "Validation Failed",
				request.getDescription(false).replace("uri=", ""));
		errorResponse.setValidationErrors(errors);
		logger.warn("Validation failed for request {}: {}", request.getDescription(false), errors);
		return errorResponse;
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public ErrorResponse handleIllegalArgumentException(IllegalArgumentException ex, WebRequest request) {
		logger.warn("Illegal argument for request {}: {}", request.getDescription(false), ex.getMessage());
		return new ErrorResponse(HttpStatus.BAD_REQUEST.value(), ex.getMessage(),
				request.getDescription(false).replace("uri=", ""));
	}

	@ExceptionHandler(BadCredentialsException.class)
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public ErrorResponse handleBadCredentialsException(BadCredentialsException ex, WebRequest request) {
		logger.warn("Bad credentials for request {}: {}", request.getDescription(false), ex.getMessage());
		return new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), "Invalid username or password", // Keep this generic
																									// for security
				request.getDescription(false).replace("uri=", ""));
	}

	@ExceptionHandler(AuthenticationException.class)
	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	public ErrorResponse handleAuthenticationException(AuthenticationException ex, WebRequest request) {
		logger.warn("Authentication failed for request {}: {}", request.getDescription(false), ex.getMessage());
		return new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), ex.getMessage(),
				request.getDescription(false).replace("uri=", ""));
	}

	@ExceptionHandler(AccessDeniedException.class)
	@ResponseStatus(HttpStatus.FORBIDDEN)
	public ErrorResponse handleAccessDeniedException(AccessDeniedException ex, WebRequest request) {
		logger.warn("Access denied for request {}: {}", request.getDescription(false), ex.getMessage());
		return new ErrorResponse(HttpStatus.FORBIDDEN.value(),
				"Access Denied: You do not have permission to access this resource.",
				request.getDescription(false).replace("uri=", ""));
	}

	@ExceptionHandler(Exception.class)
	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	public ErrorResponse handleGlobalException(Exception ex, WebRequest request) {
		logger.error("Unhandled exception for request {}:", request.getDescription(false), ex);
		return new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(),
				"An unexpected error occurred. Please try again later.", // Generic message for unknown errors
				request.getDescription(false).replace("uri=", ""));
	}
}
