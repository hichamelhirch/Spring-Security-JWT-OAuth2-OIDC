package org.sid.securityservice.web;

import lombok.RequiredArgsConstructor;
import org.sid.securityservice.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/token")
    public ResponseEntity<Map<String, String>> jwtToken(String username, String password,
                                                        Boolean withRefreshToken, String refreshToken, String grantType) {
        return authService.jwtToken(username, password, withRefreshToken, refreshToken, grantType);
    }
}
