package delivery.system.authorizationservice.integration.user;



import delivery.system.authorizationservice.config.BaseIntegrationTest;
import delivery.system.authorizationservice.models.request.AddUserRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.List;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


public  class UserIT extends BaseIntegrationTest {


    private void givenAdminSetup() throws Exception {
        givenAuthorityExists("user:read");
        givenRoleExists("ADMIN", List.of("user:read"));
    }
    private void givenUserSetup() throws Exception {
        givenAuthorityExists("user:read");
        givenRoleExists("USER", List.of("user:read"));
    }
    /*----------- addUserIntegrationTests------------------*/
    @Test
    @DisplayName("Should return 201 when user is created successfully")
    public void createUser_shouldReturn201_whenUserIsCreated() throws Exception {
        givenAdminSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername("new-user");
        request.setPassword("password");
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(content().string("User created successfully"));
    }
    @Test
        @DisplayName("Should return 400 when username is missing")
    public void createUser_shouldReturn400_whenUsernameIsMissing()throws Exception {
        givenAdminSetup();
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
        givenAdminSetup();
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
        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));
        mockMvc.perform(requestBuilder)
                .andExpect(status().isCreated())
                .andExpect(content().string("User created successfully"));
        mockMvc.perform(requestBuilder)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Conflict - Username already exists"));
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
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Role not found"));
    }
    @Test
    @DisplayName("Should return 401 when not token provided")
    public void createUser_shouldReturn401_whenNoToken()throws Exception {
        givenAdminSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }
    @Test
    @DisplayName("Should return 403 when not an admin")
    public void createUser_shouldReturn403_whenNotAdmin()throws Exception {
        givenAdminSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        request.setRoles(List.of("ADMIN"));
        mockMvc.perform(post("/api/v1/users")
                .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }
    /*----------- registerUserIntegrationTests------------------*/

    @Test
    @DisplayName("Should return 201 when user registered successfully")
    public void registerUser_shouldReturn201_whenUserIsRegistered()throws Exception {
        givenUserSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        mockMvc.perform(post("/api/v1/users/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated()).andExpect(content().string("User registered successfully"));
    }
    @Test
    @DisplayName("Should return 400 when username is missing")
    public void registerUser_shouldReturn400_whenUsernameIsMissing()throws Exception {
        givenUserSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername(null);
        request.setPassword("password");
        mockMvc.perform(post("/api/v1/users/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.message").value("Validation failed"));
    }
    @Test
    @DisplayName("Should return 400 when password is missing")
    public void registerUser_shouldReturn400_whenPasswordIsMissing()throws Exception {
        givenUserSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword(null);
        mockMvc.perform(post("/api/v1/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed"));
    }
    @Test
    @DisplayName("Should return 409 when username already exists")
    public void registerUser_shouldReturn409_whenUsernameAlreadyExists()throws Exception {
        givenUserSetup();
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/users/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request));
        mockMvc.perform(requestBuilder)
                .andExpect(status().isCreated())
                .andExpect(content().string("User registered successfully"));
        mockMvc.perform(requestBuilder)
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Conflict - Username already exists"));


    }
    @Test
    @DisplayName("Should return 404 when role does not Exist")
    public void registerUser_shouldReturn404_whenRoleNotFound()throws Exception {
        givenAuthorityExists("user:read");
        AddUserRequest request = new AddUserRequest();
        request.setUsername("chiheb");
        request.setPassword("password");
        mockMvc.perform(post("/api/v1/users/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Role not found"));
    }

}
