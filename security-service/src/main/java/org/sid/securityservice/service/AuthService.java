package org.sid.securityservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {


    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public ResponseEntity<Map<String, String>> jwtToken(String username, String password,
                                                        Boolean withRefreshToken, String refreshToken, String grantType) {

        String subject = null;
        String scope = null;

        // Gestion du flux Password Grant
        if (grantType.equals("password")) {
            // Authentifier l'utilisateur avec username et password
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // Récupérer le sujet et les autorités (scopes)
            subject = authentication.getName();
            scope = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));
        }

        // Gestion du flux Refresh Token
        else if (grantType.equals("refreshToken")) {
            if (refreshToken == null) {
                return new ResponseEntity<>(Map.of("message", "Refres Token is required"), HttpStatus.UNAUTHORIZED);
            }
            // Décoder et valider le Refresh Token
            Jwt decodedJwt = null;
            try {
                decodedJwt = jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("message", e.getMessage()), HttpStatus.UNAUTHORIZED);
            }

            // Récupérer le sujet à partir du Refresh Token
            subject = decodedJwt.getSubject();

            // Charger les détails de l'utilisateur
            UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

            // Récupérer les scopes depuis les autorités
            scope = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));
        }

        // Générer l'Access Token
        Map<String, String> idToken = new HashMap<>();
        Instant instant = Instant.now();

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken ? Duration.ofMinutes(5) : Duration.ofMinutes(30))) // 5 min pour access token, 30 min pour refresh token
                .issuer("security-service")
                .claim("scope", scope)
                .build();

        // Encoder et retourner le nouvel Access Token
        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken", jwtAccessToken);

        // Si un Refresh Token est demandé, le générer aussi
        if (withRefreshToken) {
            JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(Duration.ofMinutes(30))) // 30 min pour refresh token
                    .issuer("security-service")
                    .build();
            String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
            idToken.put("refreshToken", jwtRefreshToken);
        }
        return new ResponseEntity<>(idToken,HttpStatus.OK);
    }

}
