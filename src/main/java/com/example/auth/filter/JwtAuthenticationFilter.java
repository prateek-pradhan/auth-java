package com.example.auth.filter;

import com.example.auth.security.AuthContext;
import com.example.auth.security.SecurityContextHolder;
import com.example.auth.service.JwtService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Set;

@Component
public class JwtAuthenticationFilter implements Filter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

        try {
            String token = extractToken(httpServletRequest);

            if(token != null && jwtService.validateToken(token)) {
                String username = jwtService.getUsernameFromToken(token);
                Set<String> roles = jwtService.getRolesFromToken(token);

                AuthContext context = new AuthContext();
                context.setUsername(username);
                context.setRoles(roles);

                SecurityContextHolder.setContext(context);

                System.out.println("✅ Authenticated user: " + username + " with roles: " + roles);
            }

            filterChain.doFilter(servletRequest, servletResponse);
        }

        catch(Exception e) {
            System.err.println("❌ Authentication error: " + e.getMessage());

            filterChain.doFilter(servletRequest, servletResponse);
        }

        finally {
            SecurityContextHolder.clearContext();
        }
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if(bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException{
        System.out.println("🔒 JWT Authentication Filter initialized");
    }

    @Override
    public void destroy() {
        System.out.println("🔒 JWT Authentication Filter destroyed");
    }
}
