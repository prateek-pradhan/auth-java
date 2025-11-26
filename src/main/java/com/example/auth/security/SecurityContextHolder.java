package com.example.auth.security;

import java.util.Set;

public class SecurityContextHolder {

    private static final ThreadLocal<AuthContext> contextHolder = new ThreadLocal<>();

    public static void setContext(AuthContext context) {
        contextHolder.set(context);
    }

    public static AuthContext getContext() {
        return contextHolder.get();
    }

    public static void clearContext() {
        contextHolder.remove();
    }


    public static boolean isAuthenticated() {
        return contextHolder.get() != null;
    }

    public static String getCurrentUsername() {
        AuthContext context = contextHolder.get();
        return context != null ? context.getUsername() : null;
    }

    public static Set<String> getCurrentRoles() {
        AuthContext context = contextHolder.get();
        return context != null ? context.getRoles() : null;
    }

    public static boolean hasRole(String role) {
        AuthContext context = contextHolder.get();
        return context != null && context.hasRole(role);

    }



}
