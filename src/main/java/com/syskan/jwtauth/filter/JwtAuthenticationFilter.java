package com.syskan.jwtauth.filter;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value; // For cookie name
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.syskan.jwtauth.service.UserDetailsServiceImpl;
import com.syskan.jwtauth.util.JwtUtil;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie; // Make sure this import is present
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
	//
	@Autowired
	private JwtUtil jwtUtil;
	//
	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	@Value("${jwt.cookie.name}")
	private String jwtCookieName;

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {
		try {
			String jwt = parseJwt(request); // This method is now updated
			if (jwt != null) {
				String username = jwtUtil.extractUsername(jwt);

				if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
					UserDetails userDetails = userDetailsService.loadUserByUsername(username);

					if (jwtUtil.validateToken(jwt, userDetails)) {
						UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
								userDetails, null, userDetails.getAuthorities());
						authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						SecurityContextHolder.getContext().setAuthentication(authentication);
						log.debug("Authenticated user via JWT: {}, setting security context", username);
					} else {
						log.warn("JWT token is invalid for user: {}", username);
					}
				}
			}
		} catch (ExpiredJwtException e) {
			log.warn("JWT token is expired: {}", e.getMessage());
			clearJwtCookie(response); // Clear expired cookie
		} catch (UnsupportedJwtException | MalformedJwtException | SignatureException | IllegalArgumentException e) {
			log.warn("Invalid JWT token processing: {}", e.getMessage());
			clearJwtCookie(response); // Clear invalid cookie
		} catch (UsernameNotFoundException e) {
			log.warn("User not found for JWT: {}", e.getMessage());
			clearJwtCookie(response); // User in token doesn't exist anymore
		} catch (Exception e) {
			log.error("Cannot set user authentication: {}", e.getMessage(), e);
		}

		filterChain.doFilter(request, response);
	}

	private String parseJwt(HttpServletRequest request) {
		// 1. Try Authorization Header
		String headerAuth = request.getHeader("Authorization");
		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			return headerAuth.substring(7);
		}

		// 2. Try Cookie
		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (jwtCookieName.equals(cookie.getName())) {
					String token = cookie.getValue();
					if (StringUtils.hasText(token)) {
						return token;
					}
				}
			}
		}
		return null;
	}

	private void clearJwtCookie(HttpServletResponse response) {
		Cookie cookie = new Cookie(jwtCookieName, null);
		cookie.setPath("/");
		cookie.setMaxAge(0);
		cookie.setHttpOnly(true);
		// cookie.setSecure(true); // In production
		response.addCookie(cookie);
		log.debug("Cleared JWT cookie due to invalid/expired token.");
	}

}

//
//@Component
//public class JwtAuthenticationFilter extends OncePerRequestFilter {
//
//	private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
//
//	@Autowired
//	private JwtUtil jwtUtil;
//
//	@Autowired
//	private UserDetailsServiceImpl userDetailsService;
//
//	@Override
//	protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
//			@NonNull FilterChain filterChain) throws ServletException, IOException {
//		try {
//			String jwt = parseJwt(request);
//			if (jwt != null) {
//				String username = jwtUtil.extractUsername(jwt); // Can throw if token is malformed before validation
//
//				if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//					UserDetails userDetails = userDetailsService.loadUserByUsername(username); // Can throw
//																								// UsernameNotFoundException
//
//					if (jwtUtil.validateToken(jwt, userDetails)) {
//						UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
//								userDetails, null, userDetails.getAuthorities());
//						authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//						SecurityContextHolder.getContext().setAuthentication(authentication);
//						log.debug("Authenticated user: {}, setting security context", username);
//					} else {
//						log.warn("JWT token is invalid for user: {}", username);
//					}
//				}
//			}
//		} catch (ExpiredJwtException e) {
//			log.warn("JWT token is expired: {}", e.getMessage());
//		} catch (UnsupportedJwtException e) {
//			log.warn("JWT token is unsupported: {}", e.getMessage());
//		} catch (MalformedJwtException e) {
//			log.warn("Invalid JWT token: {}", e.getMessage());
//		} catch (SignatureException e) {
//			log.warn("Invalid JWT signature: {}", e.getMessage());
//		} catch (IllegalArgumentException e) {
//			log.warn("JWT claims string is empty or token is null: {}", e.getMessage());
//		} catch (UsernameNotFoundException e) {
//			log.warn("User not found for JWT: {}", e.getMessage());
//		} catch (Exception e) {
//			log.error("Cannot set user authentication: {}", e.getMessage(), e);
//		}
//
//		filterChain.doFilter(request, response);
//	}
//
//	private String parseJwt(HttpServletRequest request) {
//		String headerAuth = request.getHeader("Authorization");
//		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
//			return headerAuth.substring(7);
//		}
//		return null;
//	}
//}
