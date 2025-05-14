package com.syskan.jwtauth.util;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.syskan.jwtauth.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;

@Component
public class JwtUtil {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration.ms}")
	private long jwtExpirationMs;

	private Key key;

	@PostConstruct
	public void init() {
		this.key = Keys.hmacShaKeyFor(secret.getBytes());
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		try {
			return extractExpiration(token).before(new Date());
		} catch (Exception e) { // Could be various JWT exceptions if token is malformed/expired already
			return true;
		}
	}

	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		// Add custom claims if needed, e.g., roles
		if (userDetails instanceof User appUser) { // Use pattern variable
			claims.put("role", appUser.getRole().name());
		} else {
			// Handle case where UserDetails might not be your User entity (e.g. from tests)
			// Or ensure it's always your User entity.
			// For simplicity, this example assumes UserDetails is your appUser.
			// You might extract roles differently if UserDetails is a Spring Security User
			userDetails.getAuthorities().stream().findFirst() // Assuming one role per user for simplicity in this claim
					.ifPresent(authority -> claims.put("role", authority.getAuthority()));
		}
		return createToken(claims, userDetails.getUsername());
	}

	private String createToken(Map<String, Object> claims, String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
				.signWith(key, SignatureAlgorithm.HS256) // Use the key directly
				.compact();
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		if (userDetails == null)
			return false;
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
}
