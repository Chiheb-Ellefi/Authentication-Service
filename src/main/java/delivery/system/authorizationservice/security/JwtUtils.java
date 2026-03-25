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
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
            if (user == null) throw new IllegalArgumentException("User cannot be null");
            if (user.getUsername()== null || user.getUsername().isBlank())
                throw new IllegalArgumentException("Username cannot be null or blank");
            if (user.getId() == null)
                throw new IllegalStateException("Cannot generate token for user without an ID");
            if (!user.isEnabled())
                throw new IllegalStateException("Cannot generate token for disabled user");
            if (!user.isAccountNonLocked())
                throw new IllegalStateException("Cannot generate token for locked account");
            if (!user.isCredentialsNonExpired())
                throw new IllegalStateException("Cannot generate token for user with expired credentials");
            if (!user.isAccountNonExpired())
                throw new IllegalStateException("Cannot generate token for expired account");

            List<String> authorities = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());


            List<String> roles = authorities.stream()
                    .filter(a -> a.startsWith("ROLE_"))
                    .map(a -> a.substring(5))
                    .collect(Collectors.toList());

            return Jwts.builder()
                    .subject(user.getId().toString())
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
            if (token == null || token.isBlank() || token.split("\\.").length != 3)
                throw new IllegalArgumentException("Invalid token");

            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            @SuppressWarnings("unchecked")
            List<String> authoritiesStr = claims.get("authorities", List.class);

            Set<GrantedAuthority> authorities = authoritiesStr.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());

            return CustomUserDetails.builder()
                    .id(Long.parseLong(claims.getSubject()))
                    .username(claims.get("username", String.class))
                    .authorities(authorities)
                    .enabled(true)
                    .accountNonExpired(true)
                    .accountNonLocked(true)
                    .credentialsNonExpired(true)
                    .build();
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