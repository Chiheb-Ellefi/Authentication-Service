package delivery.system.authorizationservice.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import delivery.system.authorizationservice.models.others.BlacklistedTokenMetadata;
import delivery.system.authorizationservice.models.others.CustomUserDetails;
import delivery.system.authorizationservice.models.others.RevocationReason;
import delivery.system.authorizationservice.security.filters.TokenRevocationFilter;
import delivery.system.authorizationservice.security.providers.BlacklistAwareIntrospectionAuthenticationProvider;
import delivery.system.authorizationservice.services.BlacklistService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Value("${token.format}")
        private String TOKEN_FORMAT;
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain oauth2ServerConfig(HttpSecurity http,
                                                  JwtDecoder decoder,
                                                  BlacklistService blacklistService,
                                                  RegisteredClientRepository registeredClientRepository , OAuth2AuthorizationService authorizationService
                                                  ) throws Exception {

        OAuth2TokenIntrospectionAuthenticationProvider defaultProvider =
                new OAuth2TokenIntrospectionAuthenticationProvider(
                        registeredClientRepository,
                        authorizationService
                );
        BlacklistAwareIntrospectionAuthenticationProvider introspectionProvider =
                new BlacklistAwareIntrospectionAuthenticationProvider(blacklistService, defaultProvider);

        OAuth2AuthorizationServerConfigurer configurer =
                new OAuth2AuthorizationServerConfigurer();

        /*-----Add revoked access token to blacklist-----*/
        configurer.tokenRevocationEndpoint(revocation -> revocation.revocationResponseHandler((request, response, authentication) -> {
            OAuth2TokenRevocationAuthenticationToken revokedToken =
                    (OAuth2TokenRevocationAuthenticationToken) authentication;

            String jti;
            String username;
            Set<String> roles;
            LocalDateTime tokenExpiresAt;

            if ("reference".equalsIgnoreCase(TOKEN_FORMAT)) {

                OAuth2Authorization authorization = authorizationService.findByToken(
                        revokedToken.getToken(), OAuth2TokenType.ACCESS_TOKEN);

                if (authorization == null) {
                    response.setStatus(HttpServletResponse.SC_OK);
                    return;
                }

                OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
                if (accessToken == null || accessToken.getClaims() == null) {
                    response.setStatus(HttpServletResponse.SC_OK);
                    return;
                }

                Map<String, Object> tokenClaims = accessToken.getClaims();
                jti = (String) tokenClaims.get(JwtClaimNames.JTI);
                username = (String) tokenClaims.get("username");
                Object rolesClaim = tokenClaims.get("roles");
                roles = rolesClaim instanceof Collection<?>
                        ? ((Collection<?>) rolesClaim).stream().map(Object::toString).collect(Collectors.toSet())
                        : new HashSet<>();
                tokenExpiresAt = authorization.getAccessToken().getToken().getExpiresAt() != null
                        ? LocalDateTime.ofInstant(authorization.getAccessToken().getToken().getExpiresAt(), ZoneOffset.UTC)
                        : null;

            } else {

                Jwt jwt = decoder.decode(revokedToken.getToken());
                jti = jwt.getClaim(JwtClaimNames.JTI);
                username = jwt.getClaim("username");
                roles = new HashSet<>(jwt.getClaimAsStringList("roles") != null
                        ? jwt.getClaimAsStringList("roles")
                        : List.of());
                tokenExpiresAt = jwt.getExpiresAt() != null
                        ? LocalDateTime.ofInstant(jwt.getExpiresAt(), ZoneOffset.UTC)
                        : null;
            }

            BlacklistedTokenMetadata metadata = BlacklistedTokenMetadata.builder()
                    .reason(RevocationReason.USER_LOGOUT)
                    .username(username)
                    .roles(roles)
                    .jti(jti)
                    .tokenType(TOKEN_FORMAT)
                    .revokedAt(LocalDateTime.now(ZoneOffset.UTC))
                    .tokenExpiresAt(tokenExpiresAt)
                    .revokedByIp(request.getRemoteAddr())
                    .userAgent(request.getHeader("User-Agent"))
                    .revokedBy(authentication.getName())
                    .build();

            blacklistService.revokeAccessToken(jti, metadata);
            response.setStatus(HttpServletResponse.SC_OK);
        }));
        configurer.tokenIntrospectionEndpoint(introspection->introspection.authenticationProvider(introspectionProvider));
        http.securityMatcher(configurer.getEndpointsMatcher())
                .with(configurer, Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login")))
                .csrf(AbstractHttpConfigurer::disable);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        return http.build();
    }

    // -------------------------------------------------------------------------
    // Chain 2 — Form Login UI
    // Handles: /login, /error — the human-facing browser login page
    // -------------------------------------------------------------------------
    @Bean
    @Order(2)
    public SecurityFilterChain formLoginConfig(HttpSecurity http) throws Exception {
        http.securityMatcher("/login/**", "/error/**")
                .formLogin(form -> form
                .successHandler(authenticationSuccessHandler())
        )
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    // -------------------------------------------------------------------------
    // Chain 3 — REST API (stateless, Bearer token)
    // Handles: /api/** — validates JWT issued by Chain 1
    // -------------------------------------------------------------------------
    @Bean
    @Order(3)
    public SecurityFilterChain restApiConfig(HttpSecurity http,
                                             TokenRevocationFilter tokenRevocationFilter,
                                             OAuth2AuthorizationService authorizationService) throws Exception {
        http.securityMatcher("/api/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> {
            if ("reference".equalsIgnoreCase(TOKEN_FORMAT)) {
                oauth2.opaqueToken(opaque -> opaque
                        .introspector(localOpaqueTokenIntrospector(authorizationService))
                        .authenticationConverter(opaqueTokenAuthenticationConverter())
                );
            } else {
                oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()));
            }
        })
                .addFilterBefore(tokenRevocationFilter, BearerTokenAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/roles/**").hasRole("ADMIN")
                        .requestMatchers("/api/v1/authorities/**").hasRole("ADMIN")
                        .requestMatchers("/api/v1/clients/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/users").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/users/register").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, e) -> {
                            response.setContentType("application/json");
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            Map<String, Object> body = new HashMap<>();
                            body.put("status", 401);
                            body.put("error", "Unauthorized");
                            body.put("message", e.getMessage());
                            body.put("path", request.getServletPath());
                            new ObjectMapper().writeValue(response.getOutputStream(), body);
                        })
                        .accessDeniedHandler((request, response, e) -> {
                            response.setContentType("application/json");
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            Map<String, Object> body = new HashMap<>();
                            body.put("status", 403);
                            body.put("error", "Forbidden");
                            body.put("message", e.getMessage());
                            body.put("path", request.getServletPath());
                            new ObjectMapper().writeValue(response.getOutputStream(), body);
                        }));
        return http.build();
    }
    @Bean
    public OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter() {
        return (introspectedToken, principal) -> {

            // Correct way — getAttributes() returns the introspection claims map
            Map<String, Object> attributes = principal.getAttributes();

            Collection<GrantedAuthority> authorities = new ArrayList<>();

            Object authoritiesClaim = attributes.get("authorities");
            if (authoritiesClaim instanceof Collection<?> authList) {
                authList.stream()
                        .map(Object::toString)
                        .map(SimpleGrantedAuthority::new)
                        .forEach(authorities::add);
            }

            return new BearerTokenAuthentication(
                    new OAuth2IntrospectionAuthenticatedPrincipal(
                            principal.getName(),
                            attributes,
                            authorities
                    ),
                    new OAuth2AccessToken(
                            OAuth2AccessToken.TokenType.BEARER,
                            introspectedToken,
                            (Instant) attributes.get(OAuth2TokenIntrospectionClaimNames.IAT),
                            (Instant) attributes.get(OAuth2TokenIntrospectionClaimNames.EXP)
                    ),
                    authorities
            );
        };
    }
    @Bean
    public OpaqueTokenIntrospector localOpaqueTokenIntrospector(
            OAuth2AuthorizationService authorizationService) {
        return token -> {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    token, OAuth2TokenType.ACCESS_TOKEN);

            if (authorization == null) {
                throw new OAuth2IntrospectionException("Token not found");
            }

            OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();

            if (accessToken == null || !accessToken.isActive()) {
                throw new OAuth2IntrospectionException("Token is inactive");
            }

            Map<String, Object> claims = accessToken.getClaims() != null
                    ? accessToken.getClaims()
                    : new HashMap<>();

            // Build the principal from stored claims
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            Object authoritiesClaim = claims.get("authorities");
            if (authoritiesClaim instanceof Collection<?> authList) {
                authList.stream()
                        .map(Object::toString)
                        .map(SimpleGrantedAuthority::new)
                        .forEach(authorities::add);
            }

            return new OAuth2IntrospectionAuthenticatedPrincipal(
                    (String) claims.getOrDefault("username", authorization.getPrincipalName()),
                    claims,
                    authorities
            );
        };
    }
    @Bean
    public AuthorizationServerSettings serverSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();


        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public OAuth2AuthorizationConsentService auth2AuthorizationConsentService(
            RegisteredClientRepository registeredClientRepository,
            JdbcTemplate jdbcTemplate) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                if (principal == null || principal.getAuthorities() == null) return;

                Set<String> allAuthorities = principal.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());

                Set<String> roles = allAuthorities.stream()
                        .filter(a -> a.startsWith("ROLE_"))
                        .collect(Collectors.toSet());

                context.getClaims()
                        .claim("authorities", allAuthorities)
                        .claim("roles", roles)
                        .claim("username", principal.getName());
            }
        };
    }


    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> opaqueTokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                if (principal == null || principal.getAuthorities() == null) return;

                Set<String> allAuthorities = principal.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet());

                Set<String> roles = allAuthorities.stream()
                        .filter(a -> a.startsWith("ROLE_"))
                        .collect(Collectors.toSet());

                context.getClaims()
                        .claim("authorities", allAuthorities)
                        .claim("roles", roles)
                        .claim("username", principal.getName());
            }
        };
    }
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthoritiesClaimName("authorities");
        converter.setAuthorityPrefix("");
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
        return jwtConverter;
    }

    @Bean
    public FilterRegistrationBean<TokenRevocationFilter> disableAutoRegistration(TokenRevocationFilter filter) {
        FilterRegistrationBean<TokenRevocationFilter> registrationBean = new FilterRegistrationBean<>(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }


    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcOperations jdbcOperations,
            RegisteredClientRepository registeredClientRepository
    ) {
        return new JdbcOAuth2AuthorizationService(
                jdbcOperations,
                registeredClientRepository
        );
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        SavedRequestAwareAuthenticationSuccessHandler delegate =
                new SavedRequestAwareAuthenticationSuccessHandler();

        return (request, response, authentication) -> {
            Object principal = authentication.getPrincipal();

            if (principal instanceof CustomUserDetails userDetails) {
                Authentication newAuth = new UsernamePasswordAuthenticationToken(
                        userDetails.getUsername(),
                        null,
                        userDetails.getAuthorities()
                );
                SecurityContextHolder.getContext().setAuthentication(newAuth);
            }

            delegate.onAuthenticationSuccess(request, response, authentication);
        };
    }



}

