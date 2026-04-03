package delivery.system.authorizationservice.integration.user;



import delivery.system.authorizationservice.config.BaseIntegrationTest;
import delivery.system.authorizationservice.models.request.AddUserRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.List;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


public  class UserIT extends BaseIntegrationTest {


    private void givenAdminSetup() throws Exception {
        givenAuthorityExists("user:read");
        givenRoleExists("ADMIN", List.of("user:read"));
    }
    @Test
    @DisplayName("Should return 201 when user valid")
    public void createUser_ShouldReturn201_WhenValidUser() throws Exception {
        givenAdminSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername("new-user");
        request.setPassword("password");
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))  .andExpect(status().isCreated()).andExpect(content().string("User created"));
    }
    @Test
        @DisplayName("Should return 400 when username is missing")
    public void createUser_ShouldReturn400_whenUsernameIsMissing()throws Exception {
      AddUserRequest request = new AddUserRequest();
      request.setUsername(null);
      request.setPassword("password");
      request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed"));
    }
    @Test
    @DisplayName("Should return 400 when password is missing")
    public void createUser_shouldReturn400_whenPasswordIsMissing()throws Exception {
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword(null);
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed"));
    }
    @Test
    @DisplayName("Should return 409 when username already exists")
    public void createUser_shouldReturn409_whenUsernameAlreadyExists()throws Exception {
        givenAdminSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))).andExpect(status().isCreated());
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Conflict - Username already exists"));;
    }
    @Test
    @DisplayName("Should return 404 when role does not Exist")
    public void createUser_shouldReturn404_whenRoleNotFound()throws Exception {
        givenAuthorityExists("user:read");
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))  .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Role not found"));
    }
    @Test
    @DisplayName("Should return 401 when not token provided")
    public void createUser_shouldReturn401_WhenNoToken()throws Exception {
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))  .andExpect(status().isUnauthorized());
    }
    @Test
    @DisplayName("Should return 403 Forbidden when not an admin")
    public void createUser_shouldReturn403_WhenNotAdmin()throws Exception {
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))  .andExpect(status().isForbidden());
    }





}
