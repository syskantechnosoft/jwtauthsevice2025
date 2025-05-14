package com.syskan.jwtauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.syskan.jwtauth.filter.JwtAuthenticationFilter;

import jakarta.servlet.http.Cookie;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

	@Autowired
	private JwtAuthenticationFilter jwtAuthenticationFilter;

	@Autowired
	private AuthenticationProvider authenticationProvider;

	@Value("${jwt.cookie.name}")
	private String jwtCookieName;

	private static final String[] WEB_PUBLIC_URLS = { "/", "/login", "/register", "/perform_login", "/perform_register",
			"/css/**", "/js/**", // If you add JS files
			"/images/**" // If you add images
	};

	private static final String[] API_PUBLIC_URLS = { "/api/auth/**", "/v3/api-docs/**", "/swagger-ui/**",
			"/swagger-ui.html", "/h2-console/**" };

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(auth -> auth.requestMatchers(WEB_PUBLIC_URLS).permitAll()
						.requestMatchers(API_PUBLIC_URLS).permitAll()
						.requestMatchers(HttpMethod.GET, "/api/test/public").permitAll()
						// Dashboard access
						.requestMatchers("/dashboard").authenticated() // General dashboard, controller will redirect
						.requestMatchers("/customer-dashboard").hasRole("CUSTOMER").requestMatchers("/hr-dashboard")
						.hasRole("HR").requestMatchers("/manager-dashboard").hasRole("MANAGER")
						.requestMatchers("/admin-dashboard").hasRole("ADMIN")
						// API Test Endpoints (as before)
						.requestMatchers("/api/test/customer").hasAnyRole("CUSTOMER", "ADMIN", "MANAGER", "HR")
						.requestMatchers("/api/test/hr").hasAnyRole("HR", "ADMIN").requestMatchers("/api/test/manager")
						.hasAnyRole("MANAGER", "ADMIN").requestMatchers("/api/test/admin").hasRole("ADMIN")
						.requestMatchers("/api/test/any-authenticated").authenticated().anyRequest().authenticated())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authenticationProvider(authenticationProvider)
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.logout(logout -> logout.logoutUrl("/logout") // URL to trigger logout
						.addLogoutHandler((request, response, authentication) -> { // Lambda for simple cookie clearing
							Cookie cookie = new Cookie(jwtCookieName, null);
							cookie.setPath("/");
							cookie.setMaxAge(0); // Delete cookie
							cookie.setHttpOnly(true);
							// cookie.setSecure(true); // Should be true in production over HTTPS
							response.addCookie(cookie);
						}).logoutSuccessUrl("/login?logout") // Redirect after logout
						.permitAll());

		http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

		return http.build();
	}
}

//
//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity // Enables @PreAuthorize, @PostAuthorize, etc.
//public class SecurityConfig {
//
//	@Autowired
//	private JwtAuthenticationFilter jwtAuthenticationFilter;
//
//	@Autowired
//	private AuthenticationProvider authenticationProvider;
//
//	private static final String[] WEB_PUBLIC_URLS = { "/", "/login", "/register", "/perform_login", "/perform_register",
//			"/css/**", "/js/**", // If you add JS files
//			"/images/**" // If you add images
//	};
//
//	private static final String[] API_PUBLIC_URLS = { "/api/auth/**", "/v3/api-docs/**", "/swagger-ui/**",
//			"/swagger-ui.html", "/h2-console/**" // Allow H2 console access
//	};
//
//	@Bean
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		http.csrf(AbstractHttpConfigurer::disable) // Disable CSRF for stateless APIs
//				.authorizeHttpRequests(auth -> auth.requestMatchers(API_PUBLIC_URLS).permitAll()
//						.requestMatchers(WEB_PUBLIC_URLS).permitAll()
//						.requestMatchers(HttpMethod.GET, "/api/test/public").permitAll()
//						.requestMatchers("/api/test/customer").hasAnyRole("CUSTOMER", "ADMIN", "MANAGER", "HR")
//						.requestMatchers("/api/test/hr").hasAnyRole("HR", "ADMIN").requestMatchers("/api/test/manager")
//						.hasAnyRole("MANAGER", "ADMIN").requestMatchers("/api/test/admin").hasRole("ADMIN")
//						.requestMatchers("/api/test/any-authenticated").authenticated().anyRequest().authenticated()
//				// All other requests need authentication
//				).sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//				// Stateless session
//				.authenticationProvider(authenticationProvider)
//				// Set the custom authentication provider
//				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
//		// Add JWT filter
//
//		// For H2 console to work with Spring Security (iframes)
//		http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
//
//		return http.build();
//	}
//}
