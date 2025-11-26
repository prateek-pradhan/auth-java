package com.example.auth.security;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import java.util.Set;

@Data
@RequiredArgsConstructor
public class AuthContext {

    private String username;

    private Set<String> roles;

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    public boolean hasAllRoles(String... rolesToCheck) {
        if (roles == null || rolesToCheck == null) {
            return false;
        }
        for (String role: rolesToCheck) {
            if (!roles.contains(role)) {
                return false;
            }
        }

        return true;
    }

    public boolean hasAnyRole(String... rolesToCheck) {
        if (roles == null || rolesToCheck == null) {
            return false;
        }
        for (String role: rolesToCheck) {
            if (roles.contains(role)) {
                return true;
            }
        }

        return false;
    }


}
