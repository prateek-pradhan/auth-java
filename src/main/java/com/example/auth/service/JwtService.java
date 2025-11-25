package com.example.auth.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    private SecretKey getSigningKey() {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String username, Set<String> roles) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsernameFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return claims.getSubject();
    }

    @SuppressWarnings("unchecked")
    public Set<String> getRolesFromToken(String token){
        Claims claims = getClaimsFromToken(token);

        Object rolesObj = claims.get("roles");

        if (rolesObj instanceof Set) {
            return (Set<String>) rolesObj;
        } else if (rolesObj instanceof java.util.List) {
            return new java.util.HashSet<>((java.util.List<String>) rolesObj);
        }

        return new java.util.HashSet<>();
    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        }
        catch(ExpiredJwtException e) {
            System.out.println("Token expired: " + e.getMessage());
            return false;
        }
        catch (UnsupportedJwtException e) {
            System.out.println("Unsupported token: "+ e.getMessage());
            return false;
        }
        catch (MalformedJwtException e) {
            System.out.println("Malformed token: " +  e.getMessage());
            return false;
        }
        catch (SignatureException e) {
            System.out.println("Invalid signature: " + e.getMessage());
            return false;
        }
        catch (IllegalArgumentException e) {
            System.out.println("Token is empty: " + e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getClaimsFromToken(token).getExpiration();
            return expiration.before(new Date());
        }
        catch (JwtException e) {
            return true;
        }
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimsFromToken(token).getExpiration();
    }

    public Date getIssuedAtDateFromToken(String token) {
        return getClaimsFromToken(token).getIssuedAt();
    }

    public long getRemainingTimeMillis(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.getTime() - System.currentTimeMillis();
    }

}
