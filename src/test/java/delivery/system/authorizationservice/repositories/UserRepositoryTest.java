package delivery.system.authorizationservice.repositories;

import delivery.system.authorizationservice.config.TestConfig;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.utils.DummyData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;


import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@Import({TestConfig.class,DummyData.class})
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private DummyData dummyData;

    @BeforeEach
    void setUp() {
        dummyData.initializeRolesAndAuthorities();
    }

    @Test
    @DisplayName("Should find user by username")
    public void findByUsernameWhenUsernameFoundThenReturnUser() {
        User user = dummyData.getUser();
        User savedUser = userRepository.save(user);

        Optional<User> result = userRepository.findByUsername(savedUser.getUsername());

        assertTrue(result.isPresent());
        assertEquals(savedUser.getUsername(), result.get().getUsername());
        assertTrue(passwordEncoder.matches("test-password", result.get().getPassword()));
        assertEquals(savedUser.getId(), result.get().getId());
        assertTrue(result.get().getRoles().containsAll(savedUser.getRoles()));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"unknown", "", " "})
    @DisplayName("Should return empty Optional for invalid usernames")
    public void findByUsernameWhenInvalidUsernameThenReturnEmptyOptional(String username) {
        Optional<User> result = userRepository.findByUsername(username);
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("Should return true if user exists ")
    public void existsByUsernameWhenUserExistThenReturnTrue() {
        User user = dummyData.getUser();
        userRepository.save(user);
        assertTrue(userRepository.existsByUsername(user.getUsername()));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " ", "unknown"})
    @DisplayName("Should return false when the username is invalid or user doesn't exist ")
    public void existsByUsernameWhenUserNotExistThenReturnFalse(String username) {
        assertFalse(userRepository.existsByUsername(username));
    }

    @Test
    @DisplayName("Should delete user when username is valid")
    public void deleteByUsernameWhenUsernameFoundThenThenReturnOne() {
        User user = dummyData.getUser();
        userRepository.save(user);
        Long nb = userRepository.deleteByUsername(user.getUsername());
        assertEquals(1L, (long) nb);
        assertFalse(userRepository.existsByUsername(user.getUsername()));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", " ", "unknown"})
    public void deleteByUsernameWhenUsernameInvalidThenReturnZero(String username) {
        Long nb = userRepository.deleteByUsername(username);
        assertEquals(0L, (long) nb);
    }

}
