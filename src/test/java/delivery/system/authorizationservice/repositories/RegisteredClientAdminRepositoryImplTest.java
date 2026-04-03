package delivery.system.authorizationservice.repositories;




import delivery.system.authorizationservice.config.TestConfig;
import delivery.system.authorizationservice.config.TestOAuthConfig;
import delivery.system.authorizationservice.repositories.impl.RegisteredClientAdminRepositoryImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.List;
import java.util.UUID;

import static delivery.system.authorizationservice.utils.ClientHelperMethods.generateClientId;
import static delivery.system.authorizationservice.utils.ClientHelperMethods.generateClientSecret;
import static org.junit.jupiter.api.Assertions.*;


@JdbcTest
@Import({RegisteredClientAdminRepositoryImpl.class, TestOAuthConfig.class, TestConfig.class})
public class RegisteredClientAdminRepositoryImplTest {

    @Autowired
    private RegisteredClientAdminRepository registeredClientAdminRepository;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private RegisteredClient registeredClient;

    @BeforeEach
    public void setup() {
        String clientSecret = generateClientSecret();
     registeredClient= RegisteredClient.withId(UUID.randomUUID().toString()).clientId(generateClientId("TestClient")).clientSecret(passwordEncoder.encode(clientSecret))
             .scopes(s -> s.addAll(List.of("read", "write")))
             .redirectUri("http://localhost")
             .postLogoutRedirectUri("http://localhost")
             .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
     registeredClientRepository.save(registeredClient);
    }

    @Test
    public void deleteByClientIdWhenClientExistsThenConfirmUpdates() {
        registeredClientAdminRepository.deleteByClientId(registeredClient.getClientId());
        RegisteredClient result = registeredClientRepository.findByClientId(registeredClient.getClientId());
        assertNull(result);
    }
    @Test
    public void deleteByClientId_whenClientDoesNotExist_thenNothingHappens() {

        assertDoesNotThrow(() ->
                registeredClientAdminRepository.deleteByClientId("non-existent-id")
        );
    }

    @Test
    public void existsByClientNameWhenClientExistsThenReturnsTrue() {
        boolean exists = registeredClientAdminRepository.existsByClientName(registeredClient.getClientName());
        assertTrue(exists);
    }
    @Test
    public void existsByClientName_whenClientDoesNotExist_thenReturnsFalse() {
        assertFalse(registeredClientAdminRepository.existsByClientName("non-existent-name"));
    }
}