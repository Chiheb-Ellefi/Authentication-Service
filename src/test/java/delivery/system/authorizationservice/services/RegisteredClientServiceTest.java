package delivery.system.authorizationservice.services;


import delivery.system.authorizationservice.exceptions.client.ClientAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.client.ClientNotFoundException;
import delivery.system.authorizationservice.models.request.ClientRegistrationRequest;
import delivery.system.authorizationservice.models.response.ClientDetailsResponse;
import delivery.system.authorizationservice.models.response.ClientOperationResponse;
import delivery.system.authorizationservice.models.response.ClientRegistrationResponse;
import delivery.system.authorizationservice.repositories.impl.RegisteredClientAdminRepositoryImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegisteredClientServiceTest {

    @Mock
    RegisteredClientRepository registeredClientRepository;

    @Mock
    PasswordEncoder passwordEncoder;

    @Mock
    RegisteredClientAdminRepositoryImpl registeredClientAdminRepositoryImpl;

    RegisteredClientService registeredClientService;

    @Captor
    ArgumentCaptor<RegisteredClient> registeredClientCaptor;

    private final Long accessTokenTtl = 3600L;
    private final Long refreshTokenTtl = 86400L;
    private final Long authorizationCodeTtl = 600L;
    private final String tokenFormat = "self-contained";
    private final boolean requireProofKey = true;
    private final boolean requireAuthorizationConsent = false;
    private final String idTokenSignatureAlgorithm = "RS256";
    private final boolean reuseRefreshTokens = false;
    private final List<String> clientAuthenticationMethods = List.of("client_secret_basic", "client_secret_post");

    @BeforeEach
    void setUp() {
        registeredClientService = new RegisteredClientService(
                registeredClientRepository,
                passwordEncoder,
                registeredClientAdminRepositoryImpl
        );

        setField("accessTokenTtl", accessTokenTtl);
        setField("refreshTokenTtl", refreshTokenTtl);
        setField("authorizationCodeTtl", authorizationCodeTtl);
        setField("tokenFormat", tokenFormat);
        setField("requireProofKey", requireProofKey);
        setField("requireAuthorizationConsent", requireAuthorizationConsent);
        setField("idTokenSignatureAlgorithm", idTokenSignatureAlgorithm);
        setField("reuseRefreshTokens", reuseRefreshTokens);
        setField("clientAuthenticationMethods", clientAuthenticationMethods);
    }

    private void setField(String field, Object value) {
        ReflectionTestUtils.setField(registeredClientService, field, value);
    }


    private ClientRegistrationRequest buildValidRequest() {
        return ClientRegistrationRequest.builder()
                .clientName("clientName")
                .redirectUris(Set.of("http://localhost:9000/redirect"))
                .scopes(Set.of("read", "openid"))
                .postLogoutRedirectUris(Set.of("http://localhost:9000/logout"))
                .authorizationGrantTypes(Set.of("authorization_code", "client_credentials"))
                .build();
    }


    private RegisteredClient buildRegisteredClient(String clientId) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName("clientName")
                .clientSecret("encodedSecret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:9000/redirect")
                .scope("read")
                .clientSettings(ClientSettings.builder().build())
                .tokenSettings(TokenSettings.builder().build())
                .build();
    }
    /*-------registerClientTests*-----------*/

    @Test
    @DisplayName("Should throw ClientAlreadyExistsException when the clientName already exists")
    public void registerClient_ClientNameExists_ThrowsClientAlreadyExistsException(){
        ClientRegistrationRequest clientRegistrationRequest = buildValidRequest();
        when(registeredClientAdminRepositoryImpl.existsByClientName(clientRegistrationRequest.getClientName())).thenReturn(true);
        ClientAlreadyExistsException exception = assertThrows(
                ClientAlreadyExistsException.class,
                () -> registeredClientService.registerClient(clientRegistrationRequest)
        );

        assertThat(exception.getMessage())
                .isEqualTo("Client already exists: " + clientRegistrationRequest.getClientName());
    }
    @Test
    @DisplayName("Should throw ClientAlreadyExistsException when the DataIntegrityViolationException is caught")
    public void registerClient_DataIntegrityViolationException_ThrowsClientAlreadyExistsException() {
        ClientRegistrationRequest clientRegistrationRequest = buildValidRequest();

        when(registeredClientAdminRepositoryImpl.existsByClientName(clientRegistrationRequest.getClientName()))
                .thenReturn(false);

        doThrow(new DataIntegrityViolationException("unique constraint violation"))
                .when(registeredClientRepository)
                .save(any(RegisteredClient.class));

        ClientAlreadyExistsException exception = assertThrows(
                ClientAlreadyExistsException.class,
                () -> registeredClientService.registerClient(clientRegistrationRequest)
        );

        assertThat(exception.getMessage())
                .isEqualTo("Client already exists: " + clientRegistrationRequest.getClientName());
    }

    @Test
    @DisplayName("Should persist client and return raw + encoded secrets correctly")
    void registerClient_ValidRequest_PersistClientAndReturnResponse() {
        ClientRegistrationRequest request = buildValidRequest();

        when(registeredClientAdminRepositoryImpl.existsByClientName(request.getClientName()))
                .thenReturn(false);

        when(passwordEncoder.encode(anyString())).thenReturn("encoded-secret");

        ClientRegistrationResponse response = registeredClientService.registerClient(request);

        verify(registeredClientRepository).save(registeredClientCaptor.capture());
        RegisteredClient savedClient = registeredClientCaptor.getValue();


        verify(passwordEncoder).encode(anyString());

        assertNotEquals(response.getClientSecret(), savedClient.getClientSecret());

        assertEquals(request.getClientName(), savedClient.getClientName());
        assertEquals(request.getRedirectUris(), savedClient.getRedirectUris());
        assertEquals(request.getScopes(), savedClient.getScopes());

        assertEquals(response.getClientId(), savedClient.getClientId());
        assertEquals(response.getClientName(), savedClient.getClientName());
    }


    /*-------getByClientIdTests-----------*/

    @Test
    @DisplayName("Should return ClientDetailsResponse when client is found")
    public void getByClientId_ClientExists_ReturnsClientDetailsResponse() {
        RegisteredClient registeredClient = buildRegisteredClient("clientId");

        when(registeredClientRepository.findByClientId(registeredClient.getClientId()))
                .thenReturn(registeredClient);

        ClientDetailsResponse response = registeredClientService.getByClientId(registeredClient.getClientId());

        assertEquals(response.getClientId(), registeredClient.getClientId());
        assertEquals(response.getClientName(), registeredClient.getClientName());
        assertEquals(response.getScopes(), registeredClient.getScopes());
        assertEquals(response.getRedirectUris(), registeredClient.getRedirectUris());
        assertEquals(response.getPostLogoutRedirectUris(), registeredClient.getPostLogoutRedirectUris());
        assertEquals(
                response.getAuthorizationGrantTypes(),
                registeredClient.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .collect(Collectors.toSet())
        );
    }

    @Test
    @DisplayName("Should throw ClientNotFoundException when client is not found by clientId")
    public void getByClientId_ClientNotFound_ThrowsClientNotFoundException() {
        String clientId = "non-existent-client";

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        ClientNotFoundException exception = assertThrows(
                ClientNotFoundException.class,
                () -> registeredClientService.getByClientId(clientId)
        );

        assertThat(exception.getMessage()).isEqualTo("Client not found: " + clientId);
    }

    /*-------deleteClientTests-----------*/

    @Test
    @DisplayName("Should return ClientOperationResponse when client is deleted successfully")
    public void deleteClient_ClientExists_ReturnsClientOperationResponse() {
        RegisteredClient registeredClient = buildRegisteredClient("clientId");

        when(registeredClientRepository.findByClientId(registeredClient.getClientId()))
                .thenReturn(registeredClient);

        ClientOperationResponse response = registeredClientService.deleteClient(registeredClient.getClientId());

        verify(registeredClientAdminRepositoryImpl).deleteByClientId(registeredClient.getClientId());
        assertEquals(response.getClientId(), registeredClient.getClientId());
        assertEquals(response.getMessage(), "Client with id: " + registeredClient.getClientId() + " deleted successfully!");
    }

    @Test
    @DisplayName("Should throw ClientNotFoundException when client to delete is not found")
    public void deleteClient_ClientNotFound_ThrowsClientNotFoundException() {
        String clientId = "non-existent-client";

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        ClientNotFoundException exception = assertThrows(
                ClientNotFoundException.class,
                () -> registeredClientService.deleteClient(clientId)
        );

        assertThat(exception.getMessage()).isEqualTo("Client not found: " + clientId);
    }

    @Test
    @DisplayName("Should not call deleteByClientId when client is not found")
    public void deleteClient_ClientNotFound_NeverCallsDelete() {
        String clientId = "non-existent-client";

        when(registeredClientRepository.findByClientId(clientId)).thenReturn(null);

        assertThrows(ClientNotFoundException.class,
                () -> registeredClientService.deleteClient(clientId));

        verify(registeredClientAdminRepositoryImpl, never()).deleteByClientId(any());
    }
}
