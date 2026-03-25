package delivery.system.authorizationservice.security;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.models.CustomUserDetails;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;
import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.util.*;
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
    /*-----------------generateTokenTest-------------------*/
    /*-----------------generateTokenTests-------------------*/

    @Test
    @DisplayName("Should return token when user details are valid")
    public void generateToken_ValidUserDetails_ReturnToken() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);

        String token = jwtUtils.generateToken(userDetails);

        assertNotNull(token, "Token should not be null");
        assertEquals(3, token.split("\\.").length,
                "Token should have 3 parts separated by dots");

        SecretKey secretKey = Keys.hmacShaKeyFor(
                TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals(TEST_ISSUER, claims.getIssuer(), "Issuer should match");
        assertEquals(user.getId().toString(), claims.getSubject(),
                "Subject should be user ID");
        assertEquals(user.getUsername(), claims.get("username", String.class),
                "Username should match");

        @SuppressWarnings("unchecked")
        List<String> roles = claims.get("roles", List.class);
        assertTrue(roles.contains("USER"), "Roles should contain USER");

        @SuppressWarnings("unchecked")
        List<String> authorities = claims.get("authorities", List.class);
        assertTrue(authorities.contains("ROLE_USER"),
                "Authorities should contain ROLE_USER");
        assertTrue(authorities.contains("read"),
                "Authorities should contain read");
        assertTrue(authorities.contains("write"),
                "Authorities should contain write");
    }

    @Test
    @DisplayName("Should set correct expiration time on token")
    public void generateToken_ValidUser_HasCorrectExpiration() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        long beforeGeneration = System.currentTimeMillis();

        String token = jwtUtils.generateToken(userDetails);

        SecretKey secretKey = Keys.hmacShaKeyFor(
                TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        long expectedExpiration = beforeGeneration + TEST_EXPIRATION;

        assertTrue(
                Math.abs(claims.getExpiration().getTime() - expectedExpiration) < 1000,
                "Expiration should be approximately jwtExpiration ms from now"
        );
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when user is null")
    public void generateToken_NullUser_ThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> jwtUtils.generateToken(null),
                "Should throw IllegalArgumentException for null user");
    }

    @Test
    @DisplayName("Should throw IllegalStateException when user ID is null")
    public void generateToken_NullUserId_ThrowsIllegalStateException() {
        User user = createTestUser();
        user.setId(null);
        CustomUserDetails userDetails = toUserDetails(user);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertEquals("Cannot generate token for user without an ID",
                exception.getMessage());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when user is disabled")
    public void generateToken_DisabledUser_ThrowsIllegalStateException() {
        User user = createTestUser();
        user.setEnabled(false);
        CustomUserDetails userDetails = toUserDetails(user);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertEquals("Cannot generate token for disabled user",
                exception.getMessage());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when account is locked")
    public void generateToken_LockedAccount_ThrowsIllegalStateException() {
        User user = createTestUser();
        user.setAccountNonLocked(false);
        CustomUserDetails userDetails = toUserDetails(user);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertEquals("Cannot generate token for locked account",
                exception.getMessage());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when credentials are expired")
    public void generateToken_ExpiredCredentials_ThrowsIllegalStateException() {
        User user = createTestUser();
        user.setCredentialsNonExpired(false);
        CustomUserDetails userDetails = toUserDetails(user);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertEquals("Cannot generate token for user with expired credentials",
                exception.getMessage());
    }

    @Test
    @DisplayName("Should throw IllegalStateException when account is expired")
    public void generateToken_ExpiredAccount_ThrowsIllegalStateException() {
        User user = createTestUser();
        user.setAccountNonExpired(false);
        CustomUserDetails userDetails = toUserDetails(user);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> jwtUtils.generateToken(userDetails));
        assertEquals("Cannot generate token for expired account",
                exception.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" "})
    @DisplayName("Should throw IllegalArgumentException when username is null or blank")
    public void generateToken_NullOrBlankUsername_ThrowsIllegalArgumentException(
            String username) {
        User user = createTestUser();
        user.setUsername(username);
        CustomUserDetails userDetails = toUserDetails(user);

        assertThrows(IllegalArgumentException.class,
                () -> jwtUtils.generateToken(userDetails));
    }

    @Test
    @DisplayName("Should generate token successfully when user has no roles")
    public void generateToken_EmptyRoles_GeneratesTokenSuccessfully() {
        User user = createTestUser();
        user.setRoles(new HashSet<>());
        CustomUserDetails userDetails = toUserDetails(user);

        String token = jwtUtils.generateToken(userDetails);

        assertNotNull(token);
        assertFalse(token.isBlank());

        SecretKey secretKey = Keys.hmacShaKeyFor(
                TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        @SuppressWarnings("unchecked")
        List<String> rolesInToken = claims.get("roles", List.class);
        assertNotNull(rolesInToken);
        assertTrue(rolesInToken.isEmpty());
    }

    @Test
    @DisplayName("Should include all roles in token claims")
    public void generateToken_WithRoles_AllRolesIncludedInClaims() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);

        String token = jwtUtils.generateToken(userDetails);

        SecretKey secretKey = Keys.hmacShaKeyFor(
                TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        @SuppressWarnings("unchecked")
        List<String> rolesInToken = claims.get("roles", List.class);
        List<String> expectedRoles = user.getRoles().stream()
                .map(Role::getName)
                .toList();

        assertNotNull(rolesInToken);
        assertEquals(expectedRoles.size(), rolesInToken.size());
        assertTrue(rolesInToken.containsAll(expectedRoles));
    }
    /*-----------------extractUserDetailsTest-------------------*/
    @Test
    @DisplayName("Should return UserDetails when token is valid")
    public void extractUserDetails_TokenValid_ReturnUserDetails() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        String token = jwtUtils.generateToken(userDetails);

        CustomUserDetails extractedUserDetails = jwtUtils.extractUserDetails(token);

        assertNotNull(extractedUserDetails);
        assertEquals(userDetails.getId(), extractedUserDetails.getId(), "User ID should match");
        assertEquals(userDetails.getUsername(), extractedUserDetails.getUsername(), "Username should match");

        Set<String> originalAuthorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        Set<String> extractedAuthorities = extractedUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        assertTrue(extractedAuthorities.containsAll(originalAuthorities), "Authorities should contain authorities");

    }

    @ParameterizedTest
    @DisplayName("Should throw IllegalArgumentException when token is null")
    @NullSource
    public void extractUserDetails_NullToken_ThrowsIllegalArgumentException(String token) {
        assertThrows(IllegalArgumentException.class,()->jwtUtils.extractUserDetails(token));
    }
    @ParameterizedTest
    @ValueSource(strings = {""," "})
    @DisplayName("Should throw IllegalArgumentException when token is blank")
    public void extractUserDetails_BlankToken_ThrowsIllegalArgumentException(String token) {
        assertThrows(IllegalArgumentException.class,
                () -> jwtUtils.extractUserDetails(token));
    }
    @ParameterizedTest
    @ValueSource(strings = {"xxxx.yyyyy", "xxxx.yyyy.zzzz.tttt"})
    @DisplayName("Should throw IllegalArgumentException when token has invalid format")
    public void extractUserDetails_InvalidFormat_ThrowsIllegalArgumentException(String token) {
        assertThrows(IllegalArgumentException.class,
                () -> jwtUtils.extractUserDetails(token),
                "Token must contain 3 parts");
    }

    @Test
    @DisplayName("Should throw MalformedJwtException when token is malformed")
    public void extractUserDetails_MalformedToken_ThrowsMalformedJwtException() {
        String malformedToken = "header.payload.signature";

        assertThrows(MalformedJwtException.class,
                () -> jwtUtils.extractUserDetails(malformedToken));
    }
    @Test
    @DisplayName("Should throw SignatureException when token signature is invalid")
    public void extractUserDetails_InvalidSignature_ThrowsSignatureException() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        String validToken = jwtUtils.generateToken(userDetails);

        String[] parts = validToken.split("\\.");
        String tamperedToken = parts[0] + "." + parts[1] + ".tampered_signature";

        assertThrows(SignatureException.class,
                () -> jwtUtils.extractUserDetails(tamperedToken));
    }
    @Test
    @DisplayName("Should throw ExpiredJwtException when token is expired")
    public void extractUserDetails_ExpiredToken_ThrowsExpiredJwtException() throws InterruptedException {

        JwtUtils shortExpirationJwt = new JwtUtils();
        ReflectionTestUtils.setField(shortExpirationJwt, "jwtSecret", TEST_SECRET);
        ReflectionTestUtils.setField(shortExpirationJwt, "jwtExpiration", 1); // 1ms
        ReflectionTestUtils.setField(shortExpirationJwt, "issuerService", TEST_ISSUER);
        shortExpirationJwt.init();

        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        String token = shortExpirationJwt.generateToken(userDetails);

        Thread.sleep(10);

        assertThrows(ExpiredJwtException.class,
                () -> shortExpirationJwt.extractUserDetails(token));
    }
    /*-----------------validateJwtTokenTest-------------------*/
    @Test
    @DisplayName("Should return true when token is valid")
    public void validateJwtToken_ValidToken_ReturnsTrue() {
            User user = createTestUser();
            CustomUserDetails userDetails = toUserDetails(user);
            String token = jwtUtils.generateToken(userDetails);
            boolean valid = jwtUtils.validateJwtToken(token);
            assertTrue(valid);

    }

    @Test
    @DisplayName("Should return false when the signature is tampered with ")
    public void validateJwtToken_InvalidTokenSignature_ReturnsFalse() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        String validToken = jwtUtils.generateToken(userDetails);

        String[] parts = validToken.split("\\.");
        String tamperedToken = parts[0] + "." + parts[1] + ".tampered_signature";

        assertFalse(jwtUtils.validateJwtToken(tamperedToken));
    }

    @Test
    @DisplayName("Should throw MalformedJwtException when token is malformed")
    public void validateToken_MalformedToken_ThrowsMalformedJwtException() {
        String malformedToken = "header.payload.signature";
        assertFalse(jwtUtils.validateJwtToken(malformedToken));
    }
    @Test
    @DisplayName("Should throw ExpiredJwtException when token is expired")
    public void validateToken_ExpiredToken_ThrowsExpiredJwtException() throws InterruptedException {

        JwtUtils shortExpirationJwt = new JwtUtils();
        ReflectionTestUtils.setField(shortExpirationJwt, "jwtSecret", TEST_SECRET);
        ReflectionTestUtils.setField(shortExpirationJwt, "jwtExpiration", 1); // 1ms
        ReflectionTestUtils.setField(shortExpirationJwt, "issuerService", TEST_ISSUER);
        shortExpirationJwt.init();

        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        String token = shortExpirationJwt.generateToken(userDetails);

        Thread.sleep(10);

        assertFalse(shortExpirationJwt.validateJwtToken(token));
    }
    @Test
    @DisplayName("Should return false when token is null")
    public void validateJwtToken_NullToken_ReturnsFalse() {
        assertFalse(jwtUtils.validateJwtToken(null));
    }

    @Test
    @DisplayName("Should return false when token is empty string")
    public void validateJwtToken_EmptyToken_ReturnsFalse() {
        assertFalse(jwtUtils.validateJwtToken(""));
    }

    @Test
    @DisplayName("Should return false when token is blank string")
    public void validateJwtToken_BlankToken_ReturnsFalse() {
        assertFalse(jwtUtils.validateJwtToken("   "));
    }

    @Test
    @DisplayName("Should return false when token header is invalid Base64")
    public void validateJwtToken_InvalidBase64Header_ReturnsFalse() {
        String invalidBase64Token = "invalid@base64!.payload.signature";
        assertFalse(jwtUtils.validateJwtToken(invalidBase64Token));
    }
    @Test
    @DisplayName("Should return false when token payload is invalid JSON")
    public void validateJwtToken_InvalidJsonPayload_ReturnsFalse() {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS256\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{invalid-json}".getBytes());
        String invalidToken = header + "." + payload + ".signature";

        assertFalse(jwtUtils.validateJwtToken(invalidToken));
    }
    /*-----------------extractUsernameTest-------------------*/

    @Test
    @DisplayName("Should return username when token is valid")
    public void extractUsername_ValidToken_ReturnsUserName() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        String token = jwtUtils.generateToken(userDetails);
        String username = jwtUtils.extractUsername(token);
        assertEquals(username, user.getUsername());
    }
    @Test
    @DisplayName("Should throw IllegalArgumentException when the token is null")
    public void extractUsername_NullToken_ThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> jwtUtils.extractUsername(null),"Token cannot be null");
    }

    @ParameterizedTest
    @ValueSource(strings = {""," "})
    @DisplayName("Should throw IllegalArgumentException when the token is blank")
    public void extractUsername_BlankToken_ThrowsIllegalArgumentException(String token) {
        assertThrows(IllegalArgumentException.class, () -> jwtUtils.extractUsername(token),"Token cannot be blank");
    }
    @ParameterizedTest
    @ValueSource(strings={"xxxx.yyyy.","xxxx.yyyy.zzzz.tttt"})
    @DisplayName("Should throw IllegalArgumentException when the token is invalid")
    public void extractUsername_InvalidToken_ThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> jwtUtils.extractUsername("invalid"),"Token must contain 3 parts");
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when username claim is missing")
    public void extractUsername_MissingUsernameClaim_ThrowsUsernameNotFoundException() {
        SecretKey secretKey = Keys.hmacShaKeyFor(TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        String tokenWithoutUsername = Jwts.builder()
                .subject("123")
                .claim("authorities", List.of())
                .claim("roles", List.of())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .issuer("test-issuer")
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();

        assertThrows(IllegalStateException.class,
                () -> jwtUtils.extractUsername(tokenWithoutUsername));
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when username claim is blank")
    public void extractUsername_BlankUsernameClaim_ThrowsUsernameNotFoundException() {
        SecretKey secretKey = Keys.hmacShaKeyFor(TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        String tokenWithBlankUsername = Jwts.builder()
                .subject("123")
                .claim("username", "   ")
                .claim("authorities", List.of())
                .claim("roles", List.of())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .issuer("test-issuer")
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();

        assertThrows(IllegalStateException.class,
                () -> jwtUtils.extractUsername(tokenWithBlankUsername));
    }

    /*-----------------extractUseIdTest-------------------*/
    @Test
    @DisplayName("Should userId when token is valid")
    public void extractUserId_ValidToken_ReturnsUserId() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        String token = jwtUtils.generateToken(userDetails);
        Long userId = jwtUtils.extractUserId(token);
        assertEquals(userId, user.getId(),"User id must match");
    }

    @ParameterizedTest
    @NullAndEmptySource
    public void extractUserId_InvalidToken_ThrowsIllegalArgumentException(String token) {
        assertThrows(IllegalArgumentException.class, () -> jwtUtils.extractUserId(token),"Token must contain 3 parts");

    }

    @ParameterizedTest
    @ValueSource(strings = {" ", "  "})
    @DisplayName("Should throw IllegalArgumentException when token is blank")
    public void extractUserId_BlankToken_ThrowsIllegalArgumentException(String token) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> jwtUtils.extractUserId(token));
        assertEquals("Token cannot be blank", ex.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"xxxx.yyyy", "xxxx.yyyy.zzzz.tttt", "onlyonepart"})
    @DisplayName("Should throw IllegalArgumentException when token does not have 3 parts")
    public void extractUserId_WrongNumberOfParts_ThrowsIllegalArgumentException(String token) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> jwtUtils.extractUserId(token));
        assertEquals("Token must contain 3 parts", ex.getMessage());
    }

    @Test
    @DisplayName("Should throw SignatureException when token signature is tampered")
    public void extractUserId_TamperedSignature_ThrowsSignatureException() {
        User user = createTestUser();
        CustomUserDetails userDetails = toUserDetails(user);
        String validToken = jwtUtils.generateToken(userDetails);

        String[] parts = validToken.split("\\.");
        String tamperedToken = parts[0] + "." + parts[1] + ".tampered_signature";

        assertThrows(SignatureException.class,
                () -> jwtUtils.extractUserId(tamperedToken));
    }

    @Test
    @DisplayName("Should throw SignatureException when token is signed with wrong secret")
    public void extractUserId_WrongSecret_ThrowsSignatureException() {
        SecretKey wrongKey = Keys.hmacShaKeyFor(
                "completelydifferentsecretkey123456789012345".getBytes(StandardCharsets.UTF_8));
        String tokenWithWrongSecret = Jwts.builder()
                .subject("1")
                .claim("username", "test-user")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + TEST_EXPIRATION))
                .signWith(wrongKey, Jwts.SIG.HS256)
                .compact();

        assertThrows(SignatureException.class,
                () -> jwtUtils.extractUserId(tokenWithWrongSecret));
    }

    @Test
    @DisplayName("Should throw ExpiredJwtException when token is expired")
    public void extractUserId_ExpiredToken_ThrowsExpiredJwtException() throws InterruptedException {
        JwtUtils shortExpirationJwt = new JwtUtils();
        ReflectionTestUtils.setField(shortExpirationJwt, "jwtSecret", TEST_SECRET);
        ReflectionTestUtils.setField(shortExpirationJwt, "jwtExpiration", 1);
        ReflectionTestUtils.setField(shortExpirationJwt, "issuerService", TEST_ISSUER);
        shortExpirationJwt.init();

        User user = createTestUser();
        String token = shortExpirationJwt.generateToken(toUserDetails(user));
        Thread.sleep(10);

        assertThrows(ExpiredJwtException.class,
                () -> shortExpirationJwt.extractUserId(token));
    }

    @Test
    @DisplayName("Should throw IllegalStateException when subject claim is missing")
    public void extractUserId_MissingSubject_ThrowsIllegalStateException() {
        SecretKey secretKey = Keys.hmacShaKeyFor(TEST_SECRET.getBytes(StandardCharsets.UTF_8));
        String tokenWithoutSubject = Jwts.builder()
                .claim("username", "test-user")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + TEST_EXPIRATION))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> jwtUtils.extractUserId(tokenWithoutSubject));
        assertEquals("Subject is missing or  blank in JWT token", ex.getMessage());
    }

    /*-----------------isTokenExpiredTests-------------------*/

    @Test
    @DisplayName("Should return false when token is valid and not expired")
    public void isTokenExpired_ValidToken_ReturnsFalse() {
        User user = createTestUser();
        String token = jwtUtils.generateToken(toUserDetails(user));

        assertFalse(jwtUtils.isTokenExpired(token));
    }

    @Test
    @DisplayName("Should return true when token is expired")
    public void isTokenExpired_ExpiredToken_ReturnsTrue() throws InterruptedException {
        JwtUtils shortExpirationJwt = new JwtUtils();
        ReflectionTestUtils.setField(shortExpirationJwt, "jwtSecret", TEST_SECRET);
        ReflectionTestUtils.setField(shortExpirationJwt, "jwtExpiration", 1);
        ReflectionTestUtils.setField(shortExpirationJwt, "issuerService", TEST_ISSUER);
        shortExpirationJwt.init();

        User user = createTestUser();
        String token = shortExpirationJwt.generateToken(toUserDetails(user));
        Thread.sleep(10);

        assertTrue(shortExpirationJwt.isTokenExpired(token));
    }

    @Test
    @DisplayName("Should return true when token is null")
    public void isTokenExpired_NullToken_ReturnsTrue() {
        assertTrue(jwtUtils.isTokenExpired(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " "})
    @DisplayName("Should return true when token is blank or empty")
    public void isTokenExpired_BlankToken_ReturnsTrue(String token) {
        assertTrue(jwtUtils.isTokenExpired(token));
    }

    @Test
    @DisplayName("Should return true when token signature is tampered")
    public void isTokenExpired_TamperedSignature_ReturnsTrue() {
        User user = createTestUser();
        String validToken = jwtUtils.generateToken(toUserDetails(user));

        String[] parts = validToken.split("\\.");
        String tampered = parts[0] + "." + parts[1] + ".tampered_signature";

        assertTrue(jwtUtils.isTokenExpired(tampered));
    }

    @Test
    @DisplayName("Should return true when token is signed with wrong secret")
    public void isTokenExpired_WrongSecret_ReturnsTrue() {
        SecretKey wrongKey = Keys.hmacShaKeyFor(
                "completelydifferentsecretkey123456789012345".getBytes(StandardCharsets.UTF_8));
        String tokenWithWrongSecret = Jwts.builder()
                .subject("1")
                .claim("username", "test-user")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + TEST_EXPIRATION))
                .signWith(wrongKey, Jwts.SIG.HS256)
                .compact();

        assertTrue(jwtUtils.isTokenExpired(tokenWithWrongSecret));
    }

    @Test
    @DisplayName("Should return true when token is completely malformed")
    public void isTokenExpired_MalformedToken_ReturnsTrue() {
        assertTrue(jwtUtils.isTokenExpired("header.payload.signature"));
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
    private CustomUserDetails toUserDetails(User user) {
        Set<GrantedAuthority> authorities = user.getRoles().stream()
                .flatMap(role -> {
                    Set<GrantedAuthority> auths = role.getAuthorities().stream()
                            .map(a -> (GrantedAuthority) new SimpleGrantedAuthority(a.getName()))
                            .collect(Collectors.toSet());
                    auths.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
                    return auths.stream();
                })
                .collect(Collectors.toSet());

        return CustomUserDetails.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(authorities)
                .enabled(user.isEnabled())
                .accountNonExpired(user.isAccountNonExpired())
                .accountNonLocked(user.isAccountNonLocked())
                .credentialsNonExpired(user.isCredentialsNonExpired())
                .build();
    }
}
