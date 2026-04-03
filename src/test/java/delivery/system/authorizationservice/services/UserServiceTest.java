package delivery.system.authorizationservice.services;

import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.exceptions.user.PasswordDoNotMatchException;
import delivery.system.authorizationservice.exceptions.user.UserAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.user.UserNotFoundException;
import delivery.system.authorizationservice.models.request.AddUserRequest;
import delivery.system.authorizationservice.models.request.AssignRolesRequest;
import delivery.system.authorizationservice.models.request.ChangePasswordRequest;
import delivery.system.authorizationservice.models.request.UpdateUsernameRequest;
import delivery.system.authorizationservice.repositories.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleService roleService;
    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    private User createTestUser() {
        Role userRole = Role.builder().id(1L).name("USER").authorities(new HashSet<>()).build();
        return User.builder()
                .id(1L)
                .username("test-user")
                .password("encoded-password")
                .roles(new HashSet<>(Set.of(userRole)))
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .failedLoginAttempts(0)
                .build();
    }

    /*---------------- addUser ----------------*/

    @Test
    @DisplayName("Should create user when request is valid")
    public void createUser_ValidRequest_SavesUser() {
        AddUserRequest request = new AddUserRequest();
        request.setUsername("new-user");
        request.setPassword("password");
        request.setRoles(List.of("USER"));

        Role role = Role.builder().id(1L).name("USER").build();
        when(userRepository.existsByUsername("new-user")).thenReturn(false);
        when(roleService.findByName("USER")).thenReturn(role);
        when(passwordEncoder.encode("password")).thenReturn("encoded-password");

        userService.createUser(request);

        verify(userRepository).save(argThat(u ->
                u.getUsername().equals("new-user") &&
                        u.getPassword().equals("encoded-password") &&
                        u.getRoles().contains(role)
        ));
    }

    @Test
    @DisplayName("Should throw UserAlreadyExistsException when username is taken")
    public void createUser_UsernameTaken_ThrowsUserAlreadyExistsException() {
        AddUserRequest request = new AddUserRequest();
        request.setUsername("taken-user");
        request.setPassword("password");
        request.setRoles(List.of("USER"));

        when(userRepository.existsByUsername("taken-user")).thenReturn(true);

        assertThrows(UserAlreadyExistsException.class, () -> userService.createUser(request));
        verify(userRepository, never()).save(any());
    }

    /*---------------- updateUsername ----------------*/

    @Test
    @DisplayName("Should update username when new username is available")
    public void updateUsername_ValidRequest_UpdatesUsername() {
        UpdateUsernameRequest request = new UpdateUsernameRequest();
        request.setId(1L);
        request.setUsername("new-username");

        User user = createTestUser();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.existsByUsername("new-username")).thenReturn(false);

        userService.updateUsername(request);

        assertEquals("new-username", user.getUsername());
    }

    @Test
    @DisplayName("Should throw UserAlreadyExistsException when new username is taken")
    public void updateUsername_UsernameTaken_ThrowsUserAlreadyExistsException() {
        UpdateUsernameRequest request = new UpdateUsernameRequest();
        request.setId(1L);
        request.setUsername("taken-username");

        User user = createTestUser(); // username is "test-user"
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(userRepository.existsByUsername("taken-username")).thenReturn(true);

        assertThrows(UserAlreadyExistsException.class, () -> userService.updateUsername(request));
    }

    @Test
    @DisplayName("Should throw UserNotFoundException when user not found")
    public void updateUsername_UserNotFound_ThrowsUserNotFoundException() {
        UpdateUsernameRequest request = new UpdateUsernameRequest();
        request.setId(99L);
        request.setUsername("any");

        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userService.updateUsername(request));
    }

    /*---------------- deleteUser ----------------*/

    @Test
    @DisplayName("Should delete user when user exists")
    public void deleteUser_UserExists_DeletesUser() {
        User user = createTestUser();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        userService.deleteUser(1L);

        verify(userRepository).delete(user);
    }

    @Test
    @DisplayName("Should throw UserNotFoundException when user not found")
    public void deleteUser_UserNotFound_ThrowsUserNotFoundException() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userService.deleteUser(99L));
        verify(userRepository, never()).delete(any());
    }

    /*---------------- changePassword ----------------*/

    @Test
    @DisplayName("Should change password when old password matches")
    public void changePassword_PasswordMatches_ChangesPassword() {
        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setId(1L);
        request.setOldPassword("old-password");
        request.setNewPassword("new-password");

        User user = createTestUser();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("old-password", "encoded-password")).thenReturn(true);
        when(passwordEncoder.encode("new-password")).thenReturn("new-encoded-password");

        userService.changePassword(request);

        assertEquals("new-encoded-password", user.getPassword());
        assertNotNull(user.getPasswordChangedAt());
    }

    @Test
    @DisplayName("Should throw PasswordDoNotMatchException when old password is wrong")
    public void changePassword_WrongOldPassword_ThrowsPasswordDoNotMatchException() {
        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setId(1L);
        request.setOldPassword("wrong-password");
        request.setNewPassword("new-password");

        User user = createTestUser();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "encoded-password")).thenReturn(false);

        assertThrows(PasswordDoNotMatchException.class, () -> userService.changePassword(request));
        verify(passwordEncoder, never()).encode(any());
    }

    /*---------------- assignRoles ----------------*/

    @Test
    @DisplayName("Should merge new roles with existing roles")
    public void assignRoles_ValidRequest_MergesRoles() {
        Role existingRole = Role.builder().id(1L).name("USER").build();
        Role newRole = Role.builder().id(2L).name("ADMIN").build();

        User user = User.builder().id(1L).username("test-user")
                .roles(new HashSet<>(Set.of(existingRole))).build();

        AssignRolesRequest request = new AssignRolesRequest();
        request.setId(1L);
        request.setRoleNames(List.of("ADMIN"));

        when(userRepository.findByIdWithRoles(1L)).thenReturn(Optional.of(user));
        when(roleService.findByName("ADMIN")).thenReturn(newRole);

        userService.assignRoles(request);

        assertEquals(2, user.getRoles().size());
        assertTrue(user.getRoles().containsAll(Set.of(existingRole, newRole)));
    }

    /*---------------- replaceRoles ----------------*/

    @Test
    @DisplayName("Should replace all roles")
    public void replaceRoles_ValidRequest_ReplacesRoles() {
        Role existingRole = Role.builder().id(1L).name("USER").build();
        Role newRole = Role.builder().id(2L).name("ADMIN").build();

        User user = User.builder().id(1L).username("test-user")
                .roles(new HashSet<>(Set.of(existingRole))).build();

        AssignRolesRequest request = new AssignRolesRequest();
        request.setId(1L);
        request.setRoleNames(List.of("ADMIN"));

        when(userRepository.findByIdWithRoles(1L)).thenReturn(Optional.of(user));
        when(roleService.findByName("ADMIN")).thenReturn(newRole);

        userService.replaceRoles(request);

        assertEquals(1, user.getRoles().size());
        assertTrue(user.getRoles().contains(newRole));
        assertFalse(user.getRoles().contains(existingRole));
    }

    /*---------------- removeRoles ----------------*/

    @Test
    @DisplayName("Should remove specified roles")
    public void removeRoles_ValidRequest_RemovesRoles() {
        Role roleToRemove = Role.builder().id(1L).name("USER").build();
        Role roleToKeep = Role.builder().id(2L).name("ADMIN").build();

        User user = User.builder().id(1L).username("test-user")
                .roles(new HashSet<>(Set.of(roleToRemove, roleToKeep))).build();

        AssignRolesRequest request = new AssignRolesRequest();
        request.setId(1L);
        request.setRoleNames(List.of("USER"));

        when(userRepository.findByIdWithRoles(1L)).thenReturn(Optional.of(user));
        when(roleService.findByName("USER")).thenReturn(roleToRemove);

        userService.removeRoles(request);

        assertEquals(1, user.getRoles().size());
        assertTrue(user.getRoles().contains(roleToKeep));
    }

    /*---------------- account state methods ----------------*/

    @Test
    @DisplayName("Should enable account")
    public void enableAccount_UserExists_EnablesAccount() {
        User user = createTestUser();
        user.disable();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        userService.enableAccount(1L);

        assertTrue(user.isEnabled());
    }

    @Test
    @DisplayName("Should lock account and set lockedAt")
    public void lockAccount_UserExists_LocksAccount() {
        User user = createTestUser();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        userService.lockAccount(1L);

        assertFalse(user.isAccountNonLocked());
        assertNotNull(user.getLockedAt());
    }

    @Test
    @DisplayName("Should unlock account and reset failed attempts")
    public void unlockAccount_UserExists_UnlocksAccount() {
        User user = createTestUser();
        user.lock();
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        userService.unlockAccount(1L);

        assertTrue(user.isAccountNonLocked());
        assertNull(user.getLockedAt());
        assertEquals(0, user.getFailedLoginAttempts());
    }

    @Test
    @DisplayName("Should throw UserNotFoundException when user not found for any account operation")
    public void accountOperation_UserNotFound_ThrowsUserNotFoundException() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userService.lockAccount(99L));
        assertThrows(UserNotFoundException.class, () -> userService.enableAccount(99L));
        assertThrows(UserNotFoundException.class, () -> userService.disableAccount(99L));
    }
}