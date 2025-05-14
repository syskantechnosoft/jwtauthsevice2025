package com.syskan.jwtauth.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(info = @Info(title = "Auth Service API", version = "1.0.0", description = "API for user authentication and authorization with JWT.", contact = @Contact(name = "Your Name", email = "your.email@example.com"), license = @License(name = "Apache 2.0", url = "http://www.apache.org/licenses/LICENSE-2.0.html")), servers = {
		@Server(url = "http://localhost:8085", description = "Development Server") })
@SecurityScheme(name = "bearerAuth", // Can be any name, used in @SecurityRequirement
		description = "JWT auth description. Enter 'Bearer ' followed by your token.", scheme = "bearer", type = SecuritySchemeType.HTTP, bearerFormat = "JWT", in = SecuritySchemeIn.HEADER)
public class OpenApiConfig {
}
