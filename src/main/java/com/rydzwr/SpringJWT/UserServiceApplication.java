package com.rydzwr.SpringJWT;

import com.rydzwr.SpringJWT.model.Role;
import com.rydzwr.SpringJWT.model.User;
import com.rydzwr.SpringJWT.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@Profile("dev")
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));

			String password = passwordEncoder().encode("1234");

			userService.saveUser(new User(null, "Admin", password, new ArrayList<>(), null));
			userService.saveUser(new User(null, "User", password, new ArrayList<>(), null));

			userService.addRoleToUser("Admin", "ROLE_ADMIN");
			userService.addRoleToUser("User", "ROLE_USER");
		};
	}
}
