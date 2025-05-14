package com.syskan.jwtauth;

import java.util.Arrays;
import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.syskan.jwtauth.enums.Role;
import com.syskan.jwtauth.model.User;
import com.syskan.jwtauth.repo.UserRepository;

@SpringBootApplication
public class FulljwtauthserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(FulljwtauthserviceApplication.class, args);
	}

	@Bean
	CommandLineRunner initDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		return args -> {
			List<User> usersToCreate = Arrays.asList(
					User.builder().username("admin").email("admin@example.com").password("password")
							.role(Role.ROLE_ADMIN).build(),
					User.builder().username("manager").email("manager@example.com").password("password")
							.role(Role.ROLE_MANAGER).build(),
					User.builder().username("hr").email("hr@example.com").password("password").role(Role.ROLE_HR)
							.build(),
					User.builder().username("customer").email("customer@example.com").password("password")
							.role(Role.ROLE_CUSTOMER).build());

			for (User u : usersToCreate) {
				if (userRepository.findByUsername(u.getUsername()).isEmpty()) {
					u.setPassword(passwordEncoder.encode(u.getPassword()));
					userRepository.save(u);
					System.out.println(
							"Created " + u.getRole().name().substring(5) + " user: " + u.getUsername() + "/password");
				}
			}
		};
	}

}
