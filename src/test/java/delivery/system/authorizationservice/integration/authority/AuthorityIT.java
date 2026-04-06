package delivery.system.authorizationservice.integration.authority;

import delivery.system.authorizationservice.config.BaseIntegrationTest;
import delivery.system.authorizationservice.models.request.AddAuthorityRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class AuthorityIT extends BaseIntegrationTest {

    private RequestPostProcessor admin() {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    /*----------- addAuthorityIntegrationTests ------------------*/

    @Test
    @DisplayName("Should return 201 when authority is created successfully")
    public void addAuthority_shouldReturn201_whenAuthorityIsCreated() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("user:read");

        mockMvc.perform(post("/api/v1/authorities")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("user:read"));
    }

    @Test
    @DisplayName("Should return 400 when authority name is blank")
    public void addAuthority_shouldReturn400_whenNameIsBlank() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("");

        mockMvc.perform(post("/api/v1/authorities")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation")));
    }

    @Test
    @DisplayName("Should return 400 when authority name is null")
    public void addAuthority_shouldReturn400_whenNameIsNull() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest(null);

        mockMvc.perform(post("/api/v1/authorities")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation")));
    }

    @Test
    @DisplayName("Should return 400 when authority format is invalid")
    public void addAuthority_shouldReturn400_whenInvalidFormat() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("invalid-format");

        mockMvc.perform(post("/api/v1/authorities")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should return 400 when authority contains uppercase")
    public void addAuthority_shouldReturn400_whenUppercase() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("User:Read");

        mockMvc.perform(post("/api/v1/authorities")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when authority missing colon")
    public void addAuthority_shouldReturn400_whenMissingColon() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("userread");

        mockMvc.perform(post("/api/v1/authorities")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should return 400 when authority has multiple colons")
    public void addAuthority_shouldReturn400_whenMultipleColons() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("user:read:extra");

        mockMvc.perform(post("/api/v1/authorities")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should return 400 when authority contains numbers")
    public void addAuthority_shouldReturn400_whenContainsNumbers() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("user1:read");

        mockMvc.perform(post("/api/v1/authorities")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should return 409 when authority already exists")
    public void addAuthority_shouldReturn409_whenAlreadyExists() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("user:read");

        RequestBuilder requestBuilder = post("/api/v1/authorities")
                .with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        mockMvc.perform(requestBuilder)
                .andExpect(status().isCreated());

        mockMvc.perform(requestBuilder)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(containsString("Authority already exists")));
    }

    @Test
    @DisplayName("Should return 401 when no token provided")
    public void addAuthority_shouldReturn401_whenNoToken() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("user:read");

        mockMvc.perform(post("/api/v1/authorities")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should return 403 when not admin")
    public void addAuthority_shouldReturn403_whenNotAdmin() throws Exception {
        AddAuthorityRequest request = new AddAuthorityRequest("user:read");

        mockMvc.perform(post("/api/v1/authorities")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    /*----------- deleteAuthorityIntegrationTests ------------------*/

    @Test
    @DisplayName("Should return 204 when authority deleted")
    public void deleteAuthority_shouldReturn204_whenDeleted() throws Exception {
        givenAuthorityExists("user:read");

        mockMvc.perform(delete("/api/v1/authorities/user:read")
                        .with(admin()))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("Should return 404 when authority not found")
    public void deleteAuthority_shouldReturn404_whenNotFound() throws Exception {
        mockMvc.perform(delete("/api/v1/authorities/non:existent")
                        .with(admin()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value(containsString("not found")));
    }

    @Test
    @DisplayName("Should return 401 when no token provided")
    public void deleteAuthority_shouldReturn401_whenNoToken() throws Exception {
        mockMvc.perform(delete("/api/v1/authorities/user:read"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should return 403 when not admin")
    public void deleteAuthority_shouldReturn403_whenNotAdmin() throws Exception {
        givenAuthorityExists("user:read");

        mockMvc.perform(delete("/api/v1/authorities/user:read")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden());
    }
}