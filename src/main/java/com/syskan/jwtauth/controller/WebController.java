package com.syskan.jwtauth.controller;

import java.security.Principal;
import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.syskan.jwtauth.dto.LoginRequest;
import com.syskan.jwtauth.dto.RegisterRequest;
import com.syskan.jwtauth.enums.Role;
import com.syskan.jwtauth.model.User;
import com.syskan.jwtauth.service.AuthService;
import com.syskan.jwtauth.util.JwtUtil;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@Controller
public class WebController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private AuthService authService; // For registration

	@Autowired
	private JwtUtil jwtUtil;

	@Value("${jwt.cookie.name}")
	private String jwtCookieName;

	@Value("${jwt.expiration.ms}")
	private long jwtExpirationMs;

	@GetMapping("/login")
	public String loginPage(Model model, @RequestParam(value = "error", required = false) String error,
			@RequestParam(value = "logout", required = false) String logout,
			@RequestParam(value = "registered", required = false) String registered) {
		if (!model.containsAttribute("loginRequest")) { // Avoid overwriting if redirected from POST
			model.addAttribute("loginRequest", new LoginRequest());
		}
		if (error != null) {
			model.addAttribute("errorMessage", "Invalid username or password.");
		}
		if (logout != null) {
			model.addAttribute("logoutMessage", "You have been logged out successfully.");
		}
		if (registered != null) {
			model.addAttribute("successMessage", "Registration successful! Please log in.");
		}
		return "login";
	}

	@PostMapping("/perform_login")
	public String performLogin(@Valid @ModelAttribute("loginRequest") LoginRequest loginRequest,
			BindingResult bindingResult, // For @Valid
			HttpServletResponse response, RedirectAttributes redirectAttributes, Model model) {
		if (bindingResult.hasErrors()) {
			// Add loginRequest back to model to repopulate form, errors handled by
			// Thymeleaf
			model.addAttribute("loginRequest", loginRequest);
			return "login"; // Return to login page with validation errors
		}

		try {
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
			SecurityContextHolder.getContext().setAuthentication(authentication);
			User userDetails = (User) authentication.getPrincipal(); // Our User entity
			String jwt = jwtUtil.generateToken(userDetails);

			Cookie jwtCookie = new Cookie(jwtCookieName, jwt);
			jwtCookie.setHttpOnly(true);
			// jwtCookie.setSecure(true); // Enable in production (HTTPS)
			jwtCookie.setPath("/");
			jwtCookie.setMaxAge((int) (jwtExpirationMs / 1000)); // in seconds
			response.addCookie(jwtCookie);

			return "redirect:/dashboard"; // Redirect to a general dashboard dispatcher

		} catch (BadCredentialsException e) {
			redirectAttributes.addFlashAttribute("loginRequest", loginRequest); // Keep form data
			redirectAttributes.addFlashAttribute("errorMessage", "Invalid username or password.");
			return "redirect:/login?error";
		}
	}

	@GetMapping("/register")
	public String registerPage(Model model) {
		if (!model.containsAttribute("registerRequest")) {
			model.addAttribute("registerRequest", new RegisterRequest());
		}
		model.addAttribute("allRoles",
				new Role[] { Role.ROLE_CUSTOMER, Role.ROLE_HR, Role.ROLE_MANAGER, Role.ROLE_ADMIN }); // Or fewer for
																										// public
																										// registration
		return "register";
	}

	@PostMapping("/perform_register")
	public String performRegister(@Valid @ModelAttribute("registerRequest") RegisterRequest registerRequest,
			BindingResult bindingResult, Model model, RedirectAttributes redirectAttributes) {
		if (bindingResult.hasErrors()) {
			model.addAttribute("allRoles",
					new Role[] { Role.ROLE_CUSTOMER, Role.ROLE_HR, Role.ROLE_MANAGER, Role.ROLE_ADMIN });
			return "register"; // Show errors on the registration page
		}
		try {
			authService.register(registerRequest);
			redirectAttributes.addFlashAttribute("successMessage", "Registration successful! Please log in.");
			return "redirect:/login?registered";
		} catch (IllegalArgumentException e) {
			model.addAttribute("allRoles",
					new Role[] { Role.ROLE_CUSTOMER, Role.ROLE_HR, Role.ROLE_MANAGER, Role.ROLE_ADMIN });
			model.addAttribute("errorMessage", e.getMessage()); // e.g., "Username already taken"
			return "register";
		}
	}

	@GetMapping("/dashboard")
	public String mainDashboard(Principal principal) {
		if (principal == null) {
			return "redirect:/login";
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

		if (authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
			return "redirect:/admin-dashboard";
		} else if (authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_MANAGER"))) {
			return "redirect:/manager-dashboard";
		} else if (authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_HR"))) {
			return "redirect:/hr-dashboard";
		} else if (authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_CUSTOMER"))) {
			return "redirect:/customer-dashboard";
		}
		return "redirect:/login"; // Fallback
	}

	@GetMapping("/customer-dashboard")
	public String customerDashboard(Model model, Principal principal) {
		model.addAttribute("username", principal.getName());
		return "dashboards/customer-dashboard";
	}

	@GetMapping("/manager-dashboard")
	public String managerDashboard(Model model, Principal principal) {
		model.addAttribute("username", principal.getName());
		return "dashboards/manager-dashboard";
	}

	@GetMapping("/hr-dashboard")
	public String hrDashboard(Model model, Principal principal) {
		model.addAttribute("username", principal.getName());
		return "dashboards/hr-dashboard";
	}

	@GetMapping("/admin-dashboard")
	public String adminDashboard(Model model, Principal principal) {
		model.addAttribute("username", principal.getName());
		return "dashboards/admin-dashboard";
	}

	@GetMapping("/")
	public String homePage(Principal principal) {
		if (principal != null) {
			return "redirect:/dashboard";
		}
		return "redirect:/login";
	}
}
