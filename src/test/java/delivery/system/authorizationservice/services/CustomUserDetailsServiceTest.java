package delivery.system.authorizationservice.services;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.models.others.CustomUserDetails;
import delivery.system.authorizationservice.repositories.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashSet;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User createTestUser() {
        Authority readAuth = Authority.builder().id(1L).name("read").build();
        Role userRole = Role.builder()
                .id(1L)
                .name("ROLE_USER")
                .authorities(new HashSet<>(Set.of(readAuth)))
                .build();
        return User.builder()
                .id(1L)
                .username("test-user")
                .password("encoded-password")
                .roles(new HashSet<>(Set.of(userRole)))
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();
    }

    @Test
    @DisplayName("Should return UserDetails when user exists")
    public void loadUserByUsername_UserExists_ReturnsUserDetails() {
        User user = createTestUser();
        when(userRepository.findByUsernameWithRoles(user.getUsername()))
                .thenReturn(Optional.of(user));

        UserDetails result = customUserDetailsService.loadUserByUsername(user.getUsername());

        assertNotNull(result);
        assertInstanceOf(CustomUserDetails.class, result);
        CustomUserDetails details = (CustomUserDetails) result;
        assertEquals(user.getId(), details.getId());
        assertEquals(user.getUsername(), details.getUsername());
        assertEquals(user.getPassword(), details.getPassword());
        assertTrue(details.isEnabled());
        assertTrue(details.isAccountNonExpired());
        assertTrue(details.isAccountNonLocked());
        assertTrue(details.isCredentialsNonExpired());
    }

    @Test
    @DisplayName("Should map authorities correctly from roles")
    public void loadUserByUsername_UserWithRoles_AuthoritiesMappedCorrectly() {
        User user = createTestUser();
        when(userRepository.findByUsernameWithRoles(user.getUsername()))
                .thenReturn(Optional.of(user));

        UserDetails result = customUserDetailsService.loadUserByUsername(user.getUsername());

        Set<String> authorityNames = result.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        assertTrue(authorityNames.contains("ROLE_USER"));
        assertTrue(authorityNames.contains("read"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" "})
    @DisplayName("Should throw IllegalArgumentException when username is null or blank")
    public void loadUserByUsername_InvalidUsername_ThrowsIllegalArgumentException(String username) {
        assertThrows(IllegalArgumentException.class,
                () -> customUserDetailsService.loadUserByUsername(username));
        verify(userRepository, never()).findByUsernameWithRoles(anyString());
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when user does not exist")
    public void loadUserByUsername_UserNotFound_ThrowsUsernameNotFoundException() {
        when(userRepository.findByUsernameWithRoles("unknown"))
                .thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class,
                () -> customUserDetailsService.loadUserByUsername("unknown"));
    }

    @Test
    @DisplayName("Should return empty authorities when user has no roles")
    public void loadUserByUsername_UserWithNoRoles_ReturnsEmptyAuthorities() {
        User user = User.builder()
                .id(1L)
                .username("test-user")
                .password("encoded-password")
                .roles(new HashSet<>())
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();
        when(userRepository.findByUsernameWithRoles(user.getUsername()))
                .thenReturn(Optional.of(user));

        UserDetails result = customUserDetailsService.loadUserByUsername(user.getUsername());

        assertTrue(result.getAuthorities().isEmpty());
    }
}
