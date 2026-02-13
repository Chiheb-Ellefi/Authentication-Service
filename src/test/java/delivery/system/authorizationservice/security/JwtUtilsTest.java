package delivery.system.authorizationservice.security;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.models.CustomUserDetails;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;
import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class JwtUtilsTest {

    private JwtUtils jwtUtils;
    private static final String TEST_SECRET = "mySecretKeyForTestingPurposesNeedsToBeAtLeast256BitsLong12345";
    private static final int TEST_EXPIRATION = 3600000;
    private static final String TEST_ISSUER = "authorization-service";

    @BeforeEach
    public void setup()
    {
        jwtUtils = new JwtUtils();

        ReflectionTestUtils.setField(jwtUtils,"jwtSecret",TEST_SECRET);
        ReflectionTestUtils.setField(jwtUtils,"jwtExpiration",TEST_EXPIRATION);
        ReflectionTestUtils.setField(jwtUtils, "issuerService", TEST_ISSUER);
        jwtUtils.init();

    }

    @Test
    @DisplayName("Should return token when user details are valid")
    public void generateToken_ValidUserDetails_ReturnToken() {
        User user=createTestUser();
        CustomUserDetails userDetails=new CustomUserDetails(user);

        String token =jwtUtils.generateToken(userDetails);

        assertNotNull(token,"Token should not be null");
        assertEquals(3, token.split("\\.").length, "Token should have 3 parts separated by dots");

        SecretKey secretKey= Keys.hmacShaKeyFor(TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        Claims claims= Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
        assertEquals(TEST_ISSUER,claims.getIssuer(), "Issuer should match");
        assertEquals(user.getId().toString(),claims.getSubject(),"Subject should be user ID");
        assertEquals(user.getUsername(), claims.get("username", String.class), "Username should match");

        @SuppressWarnings("unchecked")
        List<String> roles=claims.get("roles", List.class);
        assertTrue(roles.contains("USER"), "Roles should contain USER");
        @SuppressWarnings("unchecked")
        List<String> authorities=claims.get("authorities", List.class);
        assertTrue(authorities.contains("ROLE_USER"), "Authorities should contain ROLE_USER");
        assertTrue(authorities.contains("read"), "Authorities should contain read");
        assertTrue(authorities.contains("write"), "Authorities should contain write");

    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when user is null")
    public void generateToken_NullUser_ThrowsException() {
        assertThrows(IllegalArgumentException.class,
                () -> jwtUtils.generateToken(null),
                "Should throw IllegalArgumentException for null user");
    }

    @Test
    @DisplayName("Should throw IllegalStateException when user is disabled")
    public void generateToken_DisabledUser_ThrowsException() {
        User user = createTestUser();
        user.setEnabled(false);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertTrue(exception.getMessage().contains("disabled"));
    }

    @Test
    @DisplayName("Should throw IllegalStateException when account is locked")
    public void generateToken_LockedAccount_ThrowsException() {
        User user = createTestUser();
        user.setAccountNonLocked(false);
        CustomUserDetails userDetails = new CustomUserDetails(user);
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertTrue(exception.getMessage().contains("locked"));
    }

    @Test
    @DisplayName("Should throw IllegalStateException when credentials are expired")
    public void generateToken_ExpiredCredentials_ThrowsException() {
        User user = createTestUser();
        user.setCredentialsNonExpired(false);
        CustomUserDetails userDetails = new CustomUserDetails(user);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertTrue(exception.getMessage().contains("expired credentials"));
    }

    @Test
    @DisplayName("Should throw IllegalStateException when account is expired")
    public void generateToken_ExpiredAccount_ThrowsException() {
        User user = createTestUser();
        user.setAccountNonExpired(false);
        CustomUserDetails userDetails = new CustomUserDetails(user);
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertTrue(exception.getMessage().contains("expired account"));
    }

    @Test
    @DisplayName("Should return UserDetails when token is valid")
    public void extractUserDetails_TokenValid_ReturnUserDetails() {
        User user = createTestUser();
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String token = jwtUtils.generateToken(userDetails);

        CustomUserDetails extractedUserDetails = jwtUtils.extractUserDetails(token);

        assertNotNull(extractedUserDetails);
        assertEquals(userDetails.getUser().getId(), extractedUserDetails.getUser().getId(), "User ID should match");
        assertEquals(userDetails.getUsername(), extractedUserDetails.getUsername(), "Username should match");

        Set<String> originalAuthorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        Set<String> extractedAuthorities = extractedUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        assertTrue(extractedAuthorities.containsAll(originalAuthorities), "Authorities should contain authorities");

    }



    private User createTestUser() {
        Set<Authority> userAuthorities = new HashSet<>();
        userAuthorities.add(createAuthority(1L, "read"));
        userAuthorities.add(createAuthority(2L, "write"));

        Role userRole = Role.builder()
                .id(1L)
                .name("USER")
                .authorities(userAuthorities)
                .build();

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);

        return User.builder()
                .id(1L)
                .username("test-user")
                .password("encoded-password")
                .roles(roles)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .failedLoginAttempts(0)
                .build();
    }

    private User createAdminUser() {
        Set<Authority> adminAuthorities = new HashSet<>();
        adminAuthorities.add(createAuthority(1L, "read"));
        adminAuthorities.add(createAuthority(2L, "write"));
        adminAuthorities.add(createAuthority(3L, "delete"));
        adminAuthorities.add(createAuthority(4L, "edit"));

        Role adminRole = Role.builder()
                .id(2L)
                .name("ADMIN")
                .authorities(adminAuthorities)
                .build();

        Set<Role> roles = new HashSet<>();
        roles.add(adminRole);

        return User.builder()
                .id(2L)
                .username("test-admin")
                .password("encoded-password")
                .roles(roles)
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .failedLoginAttempts(0)
                .build();
    }

    private Authority createAuthority(Long id, String name) {
        return Authority.builder()
                .id(id)
                .name(name)
                .build();
    }
}
