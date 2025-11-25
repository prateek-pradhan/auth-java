package com.example.auth.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Set;

@Data
@RequiredArgsConstructor
public class LoginResponse {

    private String token;

    private String username;

    private Set<String> roles;
}
