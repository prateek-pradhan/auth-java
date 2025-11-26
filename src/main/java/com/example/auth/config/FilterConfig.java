package com.example.auth.config;

import com.example.auth.filter.JwtAuthenticationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilter(JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();

        registrationBean.setFilter(filter);

        registrationBean.addUrlPatterns("/api/*");

        registrationBean.setOrder(1);

        System.out.println("🔧 JWT Filter registered for /api/* endpoints");

        return registrationBean;
    }
}
