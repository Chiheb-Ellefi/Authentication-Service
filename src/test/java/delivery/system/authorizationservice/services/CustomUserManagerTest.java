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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.List;

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
    @DisplayName("Should update user when user details are valid ")
    public void updateUser_ValidUserDetails_UpdatesUser() {

    }

}
