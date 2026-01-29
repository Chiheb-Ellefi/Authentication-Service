package delivery.system.authorizationservice.services;

import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.models.CustomUserDetails;
import delivery.system.authorizationservice.repositories.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CustomUserManagerTest {

    @Mock
    UserRepository userRepository;
    @Mock
    PasswordEncoder passwordEncoder;

    @InjectMocks
    CustomUserManager userManager;


    private User createTestUser() {
        Role userRole = Role.builder()
                .id(1L)
                .name("ROLE_USER")
                .authorities(new HashSet<>())
                .build();

        return User.builder()
                .username("test-user")
                .password("test-password")
                .roles(new HashSet<>(List.of(userRole)))
                .build();
    }

    /*----------------createUser Unit Tests-------------------*/
    @Test
    @DisplayName("Should create user when user details are valid")
    public void createUser_ValidUserDetails_SavesUser() {
        User expectedUser = createTestUser();
        CustomUserDetails userDetails = new CustomUserDetails(expectedUser);
        when(userRepository.save(any(User.class))).thenReturn(expectedUser);
        when(passwordEncoder.encode(expectedUser.getPassword())).thenReturn("encoded-password");
        userManager.createUser(userDetails);
        verify(userRepository).save(argThat(user ->
                user.getUsername().equals("test-user") && user.getPassword().equals("encoded-password")
        ));
    }

    @ParameterizedTest
    @DisplayName("Should throw IllegalArgumentException when userDetails is null")
    @NullSource
    public void createUser_NullUserDetails_ThrowsIllegalArgumentException(UserDetails userDetails) {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> userManager.createUser(userDetails)
        );

        assertEquals("User cannot be null", exception.getMessage());
        verify(passwordEncoder, never()).encode(any(String.class));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when userDetails is not CustomUserDetails")
    public void createUser_UnsupportedUserDetailsType_ThrowsIllegalArgumentException() {

        UserDetails unsupportedUserDetails = mock(UserDetails.class);

        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> userManager.createUser(unsupportedUserDetails)
        );
        assertTrue(exception.getMessage().startsWith("Unsupported UserDetails type:"));
        verify(passwordEncoder, never()).encode(any(String.class));
        verify(userRepository, never()).save(any(User.class));
    }
    /*----------------updateUser Unit Tests-------------------*/

    @Test
    @DisplayName("Should update user when user details are valid")
    public void updateUser_ValidUserDetails_UpdatesUser() {
        User existingUser = User.builder()
                .id(1L)
                .username("old-username")
                .password("old-password")
                .roles(new HashSet<>(List.of(
                        Role.builder().id(2L).name("ROLE_ADMIN").build()
                )))
                .build();
        User newUserData = User.builder()
                .id(1L)
                .username("new-username")
                .password("should-be-ignored")
                .roles(new HashSet<>(List.of(
                        Role.builder().id(1L).name("ROLE_USER").build()
                )))
                .build();

        CustomUserDetails userDetails = new CustomUserDetails(newUserData);
        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        userManager.updateUser(userDetails);

        verify(userRepository).findById(1L);
        verify(userRepository).save(argThat(savedUser ->
                savedUser.getId().equals(1L) &&
                        savedUser.getUsername().equals("new-username") &&
                        savedUser.getPassword().equals("old-password") &&
                        savedUser.getRoles().size() == 1 &&
                        savedUser.getRoles().iterator().next().getName().equals("ROLE_USER")
        ));
    }

    @ParameterizedTest
    @NullSource
    @DisplayName("Should throw an IllegalArgumentException when userDetails is null")
    public void updateUser_NullUserDetails_ThrowsIllegalArgumentException(UserDetails userDetails) {
        assertThrows(IllegalArgumentException.class, () -> userManager.updateUser(userDetails));
    }

    @Test
    @DisplayName("Should not save when user not found")
    public void updateUser_UserNotFound_DoesNotSave() {
        User user = createTestUser();
        user.setId(999L);
        CustomUserDetails userDetails = new CustomUserDetails(user);
        when(userRepository.findById(user.getId())).thenReturn(Optional.empty());

        userManager.updateUser(userDetails);

        verify(userRepository).findById(user.getId());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should keep the existing username when the username is null")
    public void updateUser_NullUsername_KeepsExistingUsername() {
        User existingUser = createTestUser();
        existingUser.setUsername("existing-username");

        User updateData = new User();
        updateData.setId(1L);
        updateData.setUsername(null);

        when(userRepository.findById(1L)).thenReturn(Optional.of(existingUser));

        userManager.updateUser(new CustomUserDetails(updateData));

        verify(userRepository).save(argThat(u ->
                u.getUsername().equals("existing-username")
        ));
    }
    /*----------------deleteUser Unit Tests-------------------*/

    @Test
    @DisplayName("Should delete user when username is valid")
    public void deleteUser_ValidUsername_DeletesUser() {
        userManager.deleteUser("username");
        verify(userRepository).deleteByUsername("username");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " "})
    @DisplayName("Should throw exception and not delete when username is invalid")
    public void deleteUser_InvalidUsername_DoesNotDeleteUser(String username) {
        assertThrows(IllegalArgumentException.class,
                () -> userManager.deleteUser(username));

        verify(userRepository, never()).deleteByUsername(any());
    }

    /*----------------userExists Unit Tests-------------------*/
    @Test
    @DisplayName("Should return a boolean when the username is valid")
    public void userExists_ValidUsername_ReturnBoolean() {
        userManager.userExists("username");
        verify(userRepository).existsByUsername("username");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " "})
    public void userExists_UsernameInvalid_ReturnFalse(String username) {
        assertFalse(userManager.userExists(username));
        verify(userRepository, never()).existsByUsername(anyString());
    }

    /*----------------loadUserByUsername Unit Tests-------------------*/
    @Test
    @DisplayName("Should return user details when user exists")
    public void loadUserByUsername_UserExists_ReturnsUser() {
        User existingUser = createTestUser();
        when(userRepository.findByUsername(existingUser.getUsername())).thenReturn(Optional.of(existingUser));

        UserDetails userDetails = userManager.loadUserByUsername(existingUser.getUsername());

        verify(userRepository).findByUsername(existingUser.getUsername());
        assertNotNull(userDetails);
        assertInstanceOf(CustomUserDetails.class, userDetails);
        assertEquals(existingUser.getUsername(), userDetails.getUsername());
        assertEquals(existingUser.getPassword(), userDetails.getPassword());
    }

    @ParameterizedTest
    @DisplayName("Should throw IllegalArgumentException when username invalid")
    @NullSource
    @ValueSource(strings = {"", " "})
    public void loadUserByUsername_InvalidUsername_ThrowsIllegalArgumentException(String username) {
        assertThrows(IllegalArgumentException.class,
                () -> userManager.loadUserByUsername(username));
        verify(userRepository, never()).findByUsername(anyString());
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when user does not exist")
    public void loadUserByUsername_UserDoesNotExist_ThrowsUsernameNotFoundException() {
        when(userRepository.findByUsername("invalidUsername")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class,
                () -> userManager.loadUserByUsername("invalidUsername"));

        verify(userRepository).findByUsername("invalidUsername");
    }


}
