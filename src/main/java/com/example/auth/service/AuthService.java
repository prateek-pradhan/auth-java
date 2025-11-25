package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.LoginResponse;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final PasswordService passwordService;
    private final UserRepository userRepository;

    @Transactional
    public LoginResponse loginUser(LoginRequest loginRequest) {
        if (loginRequest.getUsername() == null || loginRequest.getPassword() == null) {
            throw new IllegalArgumentException();
        }

        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));

        if(!user.isEnabled()) {
            throw new RuntimeException("Account is disabled. Please contact support.");
        }

        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        LoginResponse loginResponse = new LoginResponse();
        if(!passwordService.verifyPassword(loginRequest.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid Username or Password");
        }
        String token = jwtService.generateToken(user.getUsername(), user.getRoles());
        loginResponse.setRoles(user.getRoles());
        loginResponse.setUsername(user.getUsername());
        loginResponse.setToken(token);
        System.out.println("✅ User logged in successfully: " + user.getUsername());
        return loginResponse;
    }

    @Transactional
    public void register(RegisterRequest registerRequest) {
        if (registerRequest.getUsername() == null || registerRequest.getPassword() == null || registerRequest.getEmail() == null) {
            throw new IllegalArgumentException("Invalid username, email or password");
        }

        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new RuntimeException("User with email " + registerRequest.getEmail() + " already exists");
        }
        else if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new RuntimeException("User with email " + registerRequest.getEmail() + " already exists");
        }
        else if (!passwordService.isPasswordStrong(registerRequest.getPassword())) {
            throw new RuntimeException("Password not strong enough");
        }

        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordService.hashPassword(registerRequest.getPassword()));

        Set<String> roles = new HashSet<>();
        roles.add("USER");
        user.setRoles(roles);

        user.setEnabled(true);

        userRepository.save(user);

        System.out.println("✅ User registered successfully: " + user.getUsername());

    }

    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
    }

    public boolean isUsernameAvailable(String username) {
        return !userRepository.existsByUsername(username);
    }

    public boolean isEmailAvailable(String email) {
        return !userRepository.existsByEmail(email);
    }

}
