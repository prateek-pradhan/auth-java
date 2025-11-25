package com.example.auth.service;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {

    private static final int BCRYPT_ROUNDS = 12;

    public String hashPassword(String password) {
        if(password == null || password.isEmpty()){
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        return BCrypt.hashpw(password, BCrypt.gensalt(BCRYPT_ROUNDS));
    }

    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        if(plainPassword == null || hashedPassword == null) {
            return false;
        }

        try {
            return BCrypt.checkpw(plainPassword, hashedPassword);
        }
        catch (IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isPasswordStrong(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*\\d.*");

        return hasDigit && hasUpper && hasLower;
    }
}
