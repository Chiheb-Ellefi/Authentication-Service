package delivery.system.authorizationservice.config;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Value("${token.access-token-ttl}")
    private Long ACCESS_TOKEN_TTL;
    @Value("${token.refresh-token-ttl}")
    private Long REFRESH_TOKEN_TTL;
    @Value("${token.authorization-code-ttl}")
    private Long AUTHORIZATION_CODE_TTL;
    @Value("${spring.application.name}")
    private String issuerService;
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain oauth2ServerConfig(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer configurer = new OAuth2AuthorizationServerConfigurer();
        RequestMatcher requestMatcher = configurer.getEndpointsMatcher();
        http.securityMatcher(requestMatcher)
                .with(configurer, Customizer.withDefaults())
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated());
        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login")
                ));
        http.csrf(AbstractHttpConfigurer::disable);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain authenticationConfig(HttpSecurity http)  throws Exception {
        http.formLogin(Customizer.withDefaults());
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests.requestMatchers("/","/login/**","/error/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public AuthorizationServerSettings serverSettings() {
        return AuthorizationServerSettings.builder()
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient client=RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("clientId")
                .clientSecret(passwordEncoder().encode("secret"))
                .redirectUri("http://localhost:9000/hello")
                .clientName("clientName")

                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)

                .postLogoutRedirectUri("http://localhost:9000/")

                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")

                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(ACCESS_TOKEN_TTL))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .authorizationCodeTimeToLive(Duration.ofSeconds(AUTHORIZATION_CODE_TTL))
                        .refreshTokenTimeToLive(Duration.ofSeconds(REFRESH_TOKEN_TTL))
                        .reuseRefreshTokens(true)
                        .build())
                .build();
        var jdbc = new JdbcRegisteredClientRepository(jdbcTemplate);

        RegisteredClient existing = jdbc.findByClientId("clientId");
        if (existing != null) {
            client = RegisteredClient.from(client)
                    .id(existing.getId())
                    .build();
        }
        jdbc.save(client);

        return jdbc;
    }

    /*Use keystore or database to store the key in prod*/
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException, JOSEException {
        KeyPairGenerator  keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey= (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey= (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey=new RSAKey.Builder(publicKey).privateKey(privateKey).keyIDFromThumbprint().build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);

    }

    @Bean
    public OAuth2AuthorizationConsentService auth2AuthorizationConsentService(RegisteredClientRepository registeredClientRepository,JdbcTemplate jdbcTemplate) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate,registeredClientRepository);
    }

    
}
