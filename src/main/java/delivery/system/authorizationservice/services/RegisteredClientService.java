package delivery.system.authorizationservice.services;

import delivery.system.authorizationservice.exceptions.client.ClientAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.client.ClientNotFoundException;
import delivery.system.authorizationservice.models.request.ClientRegistrationRequest;
import delivery.system.authorizationservice.models.response.ClientDetailsResponse;
import delivery.system.authorizationservice.models.response.ClientOperationResponse;
import delivery.system.authorizationservice.models.response.ClientRegistrationResponse;
import delivery.system.authorizationservice.repositories.impl.RegisteredClientAdminRepositoryImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static delivery.system.authorizationservice.utils.ClientHelperMethods.generateClientId;
import static delivery.system.authorizationservice.utils.ClientHelperMethods.generateClientSecret;

@Service
@RequiredArgsConstructor
public class RegisteredClientService {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final RegisteredClientAdminRepositoryImpl registeredClientAdminRepository;

    @Value("${token.access-token-ttl}")
    private Long accessTokenTtl;

    @Value("${token.format}")
    private String tokenFormat;

    @Value("${token.refresh-token-ttl}")
    private Long refreshTokenTtl;
    @Value("${token.reuse-refresh-tokens}")
    private boolean reuseRefreshTokens;
    @Value("${token.id-token-signature-algorithm}")
    private String idTokenSignatureAlgorithm;

    @Value("${token.authorization-code-ttl}")
    private Long authorizationCodeTtl;

    @Value("${client.require-proof-key}")
    private boolean requireProofKey;


    @Value("${client.require-authorization-consent}")
    private boolean requireAuthorizationConsent;
    @Value("${auth.client-authentication-methods}")
    private List<String> clientAuthenticationMethods;

    public ClientRegistrationResponse registerClient(ClientRegistrationRequest request) {
        if (registeredClientAdminRepository.existsByClientName(request.getClientName())) {
            throw new ClientAlreadyExistsException("Client already exists: " + request.getClientName());
        }

        String clientId = generateClientId(request.getClientName());
        String rawSecret = generateClientSecret();

        try {
            RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientId)
                    .clientName(request.getClientName())
                    .clientSecret(passwordEncoder.encode(rawSecret))
                    .clientAuthenticationMethods(methods ->
                            clientAuthenticationMethods.stream()
                                    .map(ClientAuthenticationMethod::new)
                                    .forEach(methods::add))
                    .authorizationGrantTypes(grantTypes ->
                            request.getAuthorizationGrantTypes().stream()
                                    .map(AuthorizationGrantType::new)
                                    .forEach(grantTypes::add))
                    .redirectUris(uris -> uris.addAll(request.getRedirectUris()))
                    .postLogoutRedirectUris(uris -> uris.addAll(request.getPostLogoutRedirectUris()))
                    .scopes(scopes -> scopes.addAll(request.getScopes()))
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(requireProofKey)
                            .requireAuthorizationConsent(requireAuthorizationConsent)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofSeconds(accessTokenTtl))
                            .accessTokenFormat(new OAuth2TokenFormat(tokenFormat))
                            .authorizationCodeTimeToLive(Duration.ofSeconds(authorizationCodeTtl))
                            .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenTtl))
                            .reuseRefreshTokens(reuseRefreshTokens)
                            .idTokenSignatureAlgorithm(SignatureAlgorithm.valueOf(idTokenSignatureAlgorithm))
                            .build())
                    .build();

            registeredClientRepository.save(registeredClient);

        } catch (DataIntegrityViolationException e) {
            throw new ClientAlreadyExistsException("Client already exists: " + request.getClientName());
        }

        return ClientRegistrationResponse.builder()
                .clientId(clientId)
                .clientSecret(rawSecret)
                .clientName(request.getClientName())
                .build();
    }

    public ClientDetailsResponse getByClientId(String clientId) {
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) throw new ClientNotFoundException("Client not found: " + clientId);
        return ClientDetailsResponse.builder()
                .clientId(client.getClientId())
                .clientName(client.getClientName())
                .scopes(client.getScopes())
                .redirectUris(client.getRedirectUris())
                .authorizationGrantTypes(client.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).collect(Collectors.toSet()))
                .postLogoutRedirectUris(client.getPostLogoutRedirectUris())
                .build();
    }

    public ClientOperationResponse deleteClient(String clientId) {
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) throw new ClientNotFoundException("Client not found: " + clientId);
        registeredClientAdminRepository.deleteByClientId(clientId);
        return ClientOperationResponse.builder().message("Client with id: "+ clientId+" deleted successfully!").clientId(clientId).build();
    }



}
