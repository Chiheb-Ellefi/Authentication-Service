package delivery.system.authorizationservice.integration.role;

import delivery.system.authorizationservice.config.BaseIntegrationTest;
import delivery.system.authorizationservice.models.request.AddRoleRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class RoleIT extends BaseIntegrationTest {

    private RequestPostProcessor admin() {
        return jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    private void givenAuthoritySetup() throws Exception {
        givenAuthorityExists("user:write");
    }

    /*----------- getAllRoles ------------------*/

    @Test
    @DisplayName("Should return 200 with empty list")
    public void getAllRoles_shouldReturnEmpty() throws Exception {
        mockMvc.perform(get("/api/v1/roles").with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    @DisplayName("Should return 200 with roles list")
    public void getAllRoles_shouldReturnList() throws Exception {
        givenAuthoritySetup();
        givenRoleExists("ADMIN", List.of("user:write"));

        mockMvc.perform(get("/api/v1/roles").with(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$[0].authorities[0]").value("user:write"));
    }

    /*----------- addRole ------------------*/

    @Test
    @DisplayName("Should return 201 when role created")
    public void addRole_shouldReturn201_whenCreated() throws Exception {
        givenAuthoritySetup();

        AddRoleRequest request = new AddRoleRequest();
        request.setName("ADMIN");
        request.setAuthorities(List.of("user:write"));

        mockMvc.perform(post("/api/v1/roles")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$.authorities[0]").value("user:write"));
    }

    @Test
    @DisplayName("Should accept lowercase role and normalize")
    public void addRole_shouldAcceptLowercase() throws Exception {
        givenAuthoritySetup();

        AddRoleRequest request = new AddRoleRequest();
        request.setName("admin");
        request.setAuthorities(List.of("user:write"));

        mockMvc.perform(post("/api/v1/roles")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("ROLE_ADMIN"));
    }

    @Test
    @DisplayName("Should return 400 when role invalid format")
    public void addRole_shouldReturn400_whenInvalidFormat() throws Exception {
        givenAuthoritySetup();

        AddRoleRequest request = new AddRoleRequest();
        request.setName("ADMIN1");
        request.setAuthorities(List.of("user:write"));

        mockMvc.perform(post("/api/v1/roles")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(containsString("Validation failed")));
    }

    @Test
    @DisplayName("Should return 400 when authorities empty")
    public void addRole_shouldReturn400_whenAuthoritiesEmpty() throws Exception {
        AddRoleRequest request = new AddRoleRequest();
        request.setName("ADMIN");
        request.setAuthorities(List.of());

        mockMvc.perform(post("/api/v1/roles")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should return 404 when authority not found")
    public void addRole_shouldReturn404_whenAuthorityNotFound() throws Exception {
        AddRoleRequest request = new AddRoleRequest();
        request.setName("ADMIN");
        request.setAuthorities(List.of("non:existent"));

        mockMvc.perform(post("/api/v1/roles")
                        .with(admin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Should return 409 when role already exists")
    public void addRole_shouldReturn409_whenAlreadyExists() throws Exception {
        givenAuthoritySetup();

        AddRoleRequest request = new AddRoleRequest();
        request.setName("ADMIN");
        request.setAuthorities(List.of("user:write"));

        RequestBuilder rb = post("/api/v1/roles")
                .with(admin())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));

        mockMvc.perform(rb).andExpect(status().isCreated());
        mockMvc.perform(rb)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(containsString("Role already exists")));
    }

    /*----------- deleteRole ------------------*/

    @Test
    @DisplayName("Should return 204 when role deleted")
    public void deleteRole_shouldReturn204() throws Exception {
        givenAuthoritySetup();
        givenRoleExists("ADMIN", List.of("user:write"));

        mockMvc.perform(delete("/api/v1/roles/ADMIN").with(admin()))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("Should return 404 when role not found")
    public void deleteRole_shouldReturn404() throws Exception {
        mockMvc.perform(delete("/api/v1/roles/UNKNOWN").with(admin()))
                .andExpect(status().isNotFound());
    }
}