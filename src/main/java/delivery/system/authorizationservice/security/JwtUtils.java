package delivery.system.authorizationservice.security;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.models.CustomUserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtUtils {
    @Value("${token.secret}")
    private String jwtSecret;

    @Value("${token.access-token-ttl}")
    private int jwtExpiration;
    @Value("${spring.application.name}")
    private String issuerService;
    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
    public String generateToken(CustomUserDetails user) {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        if (user.getUsername() == null || user.getUsername().isBlank()) {
            throw new IllegalArgumentException("Username cannot be null or blank");
        }
        if (user.getUser().getId() == null) {
            throw new IllegalStateException("Cannot generate token for user without an ID");
        }
        if (!user.isEnabled()) {
            throw new IllegalStateException("Cannot generate token for disabled user");
        }
        if (!user.isAccountNonLocked()) {
            throw new IllegalStateException("Cannot generate token for locked account");
        }
        if (!user.isCredentialsNonExpired()) {
            throw new IllegalStateException("Cannot generate token for user with expired credentials");
        }
        if (!user.isAccountNonExpired()) {
            throw new IllegalStateException("Cannot generate token for expired account");
        }
        if (user.getUser().getRoles() == null) {
            throw new IllegalStateException("User roles cannot be null");
        }

        List<String> authorities = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        List<String> roles = user.getUser().getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        return Jwts.builder()
                .subject(user.getUser().getId().toString())
                .claim("username", user.getUsername())
                .claim("authorities", authorities)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .issuer(issuerService)
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public CustomUserDetails extractUserDetails(String token) {
        if(token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        if(token.isBlank()) {
            throw new IllegalArgumentException("Token cannot be blank");
        }
        if(token.split("\\.").length!=3){
            throw new IllegalArgumentException("Token must contain 3 parts");
        }
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        @SuppressWarnings("unchecked")
        List<String> authoritiesStr = claims.get("authorities", List.class);

        Set<Authority> authorities = authoritiesStr.stream()
                .filter(auth -> !auth.startsWith("ROLE_"))
                .map(authName -> Authority.builder()
                        .name(authName)
                        .build())
                .collect(Collectors.toSet());
        Set<Role> roles = authoritiesStr.stream()
                .filter(auth -> auth.startsWith("ROLE_"))
                .map(auth -> auth.substring(5))
                .map(roleName -> Role.builder().name(roleName).authorities(authorities).build())
                .collect(Collectors.toSet());


        User user = User.builder()
                .id(Long.parseLong(claims.getSubject()))
                .username(claims.get("username", String.class))
                .roles(roles)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .failedLoginAttempts(0)
                .build();
            return new CustomUserDetails(user);
    }

    public boolean validateJwtToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);
            log.debug("JWT token validated successfully");
            return true;
        } catch (io.jsonwebtoken.security.SignatureException e) {
            log.error("Invalid JWT signature - possible token tampering: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Malformed JWT token - invalid structure: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT token for user: {}", e.getClaims().getSubject());
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty or null: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error validating JWT token: {}", e.getMessage(), e);
        }
        return false;
    }

    public String extractUsername(String token) {
        if (token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        if (token.isBlank()) {
            throw new IllegalArgumentException("Token cannot be blank");
        }
        if (token.split("\\.").length != 3) {
            throw new IllegalArgumentException("Token must contain 3 parts");
        }
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        String username = claims.get("username", String.class);
        if (username == null || username.isBlank()) {
            throw new IllegalStateException(
                    "Username claim is missing or blank in JWT token");
        }
        return username;
    }

    public Long extractUserId(String token) {
        if(token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        if(token.isBlank()) {
            throw new IllegalArgumentException("Token cannot be blank");
        }
        if(token.split("\\.").length!=3){
            throw new IllegalArgumentException("Token must contain 3 parts");
        }
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        if (claims.getSubject()==null || claims.getSubject().isBlank()) {
            throw new IllegalStateException("Subject is missing or  blank in JWT token");
        }
        return Long.parseLong(claims.getSubject());
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }
}