package delivery.system.authorizationservice.integration.client;

import delivery.system.authorizationservice.config.BaseIntegrationTest;
import delivery.system.authorizationservice.models.request.ClientRegistrationRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.Set;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@Sql(scripts = "/sql/schema.sql", executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD)
public class ClientIT extends BaseIntegrationTest {

    private RequestPostProcessor admin() {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    private ClientRegistrationRequest validRequest() {
        return ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("https://example.com/callback"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("openid"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .build();
    }

    /*----------- registerClient ------------------*/

    @Test
    @DisplayName("Should return 201 when client is registered successfully")
    public void registerClient_shouldReturn201_whenClientIsRegistered() throws Exception {
        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.clientId", notNullValue()))
                .andExpect(jsonPath("$.clientSecret", notNullValue()))
                .andExpect(jsonPath("$.clientName").value("my-client"));

    }

    @Test
    @DisplayName("Should support multiple scopes and grant types")
    public void registerClient_shouldSupportMultipleValues() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("https://example.com/callback"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("openid", "profile"))
                .authorizationGrantTypes(Set.of("authorization_code", "refresh_token"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.clientId", notNullValue()))
                .andExpect(jsonPath("$.clientSecret", notNullValue()))
                .andExpect(jsonPath("$.clientName").value("my-client"));
    }
    @Test
    @DisplayName("Should return 400 when redirect URI is malformed")
    public void registerClient_shouldReturn400_whenMalformedUri() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("http:/bad-url"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("openid"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should return 400 when clientName is blank")
    public void registerClient_shouldReturn400_whenClientNameIsBlank() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("")
                .redirectUris(Set.of("https://example.com/callback"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("openid"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when redirectUris is empty")
    public void registerClient_shouldReturn400_whenRedirectUrisIsEmpty() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of())
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("openid"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when redirectUri format is invalid")
    public void registerClient_shouldReturn400_whenRedirectUriFormatIsInvalid() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("not-a-valid-uri"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("openid"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when scopes is empty")
    public void registerClient_shouldReturn400_whenScopesIsEmpty() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("https://example.com/callback"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of())
                .authorizationGrantTypes(Set.of("authorization_code"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when scope is not allowed")
    public void registerClient_shouldReturn400_whenScopeIsNotAllowed() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("https://example.com/callback"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("invalid_scope"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when authorizationGrantTypes is empty")
    public void registerClient_shouldReturn400_whenGrantTypesIsEmpty() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("https://example.com/callback"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("openid"))
                .authorizationGrantTypes(Set.of())
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when grant type is not allowed")
    public void registerClient_shouldReturn400_whenGrantTypeIsNotAllowed() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("https://example.com/callback"))
                .postLogoutRedirectUris(Set.of("https://example.com/logout"))
                .scopes(Set.of("openid"))
                .authorizationGrantTypes(Set.of("invalid_grant"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when postLogoutRedirectUris is empty")
    public void registerClient_shouldReturn400_whenPostLogoutRedirectUrisIsEmpty() throws Exception {
        ClientRegistrationRequest request = ClientRegistrationRequest.builder()
                .clientName("my-client")
                .redirectUris(Set.of("https://example.com/callback"))
                .postLogoutRedirectUris(Set.of())
                .scopes(Set.of("openid"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .build();

        mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 409 when client name already exists")
    public void registerClient_shouldReturn409_whenClientAlreadyExists() throws Exception {
        RequestBuilder rb = MockMvcRequestBuilders.post("/api/v1/clients")
                .with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(validRequest()));

        mockMvc.perform(rb)
                .andExpect(status().isCreated());

        mockMvc.perform(rb)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(containsString("already exists")));
    }

    @Test
    @DisplayName("Should return 401 when no token provided for registerClient")
    public void registerClient_shouldReturn401_whenNoToken() throws Exception {
        mockMvc.perform(post("/api/v1/clients")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should return 403 when not an admin for registerClient")
    public void registerClient_shouldReturn403_whenNotAdmin() throws Exception {
        mockMvc.perform(post("/api/v1/clients")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isForbidden());
    }

    /*----------- getByClientId ------------------*/

    @Test
    @DisplayName("Should return 200 with client details when client exists")
    public void getByClientId_shouldReturn200_whenClientExists() throws Exception {
        String responseBody = mockMvc.perform(post("/api/v1/clients")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        String clientId = objectMapper.readTree(responseBody).get("clientId").asString();

        mockMvc.perform(get("/api/v1/clients/" + clientId).with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clientId").value(clientId))
                .andExpect(jsonPath("$.clientName").value("my-client"))
                .andExpect(jsonPath("$.scopes").isArray())
                .andExpect(jsonPath("$.authorizationGrantTypes").isArray())
                .andExpect(jsonPath("$.redirectUris").isArray())
                .andExpect(jsonPath("$.postLogoutRedirectUris").isArray());
    }

    @Test
    @DisplayName("Should return 404 when client does not exist")
    public void getByClientId_shouldReturn404_whenClientNotFound() throws Exception {
        mockMvc.perform(get("/api/v1/clients/non-existent-client-id").with(admin()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value(containsString("not found")));
    }

    @Test
    @DisplayName("Should return 401 when no token provided for getByClientId")
    public void getByClientId_shouldReturn401_whenNoToken() throws Exception {
        mockMvc.perform(get("/api/v1/clients/some-client-id"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should return 403 when not an admin for getByClientId")
    public void getByClientId_shouldReturn403_whenNotAdmin() throws Exception {
        mockMvc.perform(get("/api/v1/clients/some-client-id")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }
}