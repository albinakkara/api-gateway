package com.telemedicine.api_gateway.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private final JwtUtil jwtUtil = new JwtUtil();

    @Test
    void generateToken_andExtractClaims_workCorrectly() {
        String email = "user@example.com";
        String role = "PATIENT";

        String token = jwtUtil.generateToken(email, role);

        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertTrue(jwtUtil.validate(token));

        String extractedEmail = jwtUtil.extractEmail(token);
        String extractedRole = jwtUtil.extractRole(token);

        assertEquals(email, extractedEmail);
        assertEquals(role, extractedRole);
    }
}
