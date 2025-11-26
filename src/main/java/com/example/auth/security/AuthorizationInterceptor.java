package com.example.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;

@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object handler) throws Exception {
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }

        HandlerMethod handlerMethod = (HandlerMethod) handler;

        if(handlerMethod.hasMethodAnnotation(RequiresAuth.class)) {
            if(!SecurityContextHolder.isAuthenticated()) {
                httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpServletResponse.setContentType("application/json");
                httpServletResponse.getWriter().write("{\"error\": \"Authentication required\"}");
                return false;
            }
        }

        RequiresRole requiresRole = handlerMethod.getMethodAnnotation(RequiresRole.class);
        if(requiresRole != null) {
            AuthContext context = SecurityContextHolder.getContext();

            if(context == null) {
                httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpServletResponse.setContentType("application/json");
                httpServletResponse.getWriter().write("{\"error\": \"Authentication required\"}");
                return false;
            }

            String[] requiredRoles = requiresRole.value();

            boolean hasRole = Arrays.stream(requiredRoles).anyMatch(role -> context.getRoles().contains(role));

            if(!hasRole) {
                httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                httpServletResponse.setContentType("application/json");
                httpServletResponse.getWriter().write(
                        "{\"error\": \"Insufficient permissions. Required roles: " +
                                Arrays.toString(requiredRoles) + "\"}"
                );
                return false;
            }
        }

        return true;
    }
}
