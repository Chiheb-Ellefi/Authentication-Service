package delivery.system.authorizationservice.repositories;

import delivery.system.authorizationservice.config.TestConfig;
import delivery.system.authorizationservice.entities.Role;
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

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@Import({DummyData.class, TestConfig.class})
public class RoleRepositoryTest {
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private DummyData dummyData;


    @BeforeEach
    void setUp() {
        dummyData.initializeRolesAndAuthorities();
    }
    @Test
    @DisplayName("Should find role when name valid")
    public void findByNameWhenNameValidThenReturnRole() {
        Optional<Role> roleUser = roleRepository.findByName("ROLE_USER");
        Optional<Role> adminRole = roleRepository.findByName("ROLE_ADMIN");
        assertTrue(roleUser.isPresent());
        assertTrue(adminRole.isPresent());
        assertEquals("ROLE_USER", roleUser.get().getName());
        assertEquals("ROLE_ADMIN", adminRole.get().getName());
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {""," ","unknown"})
    public void findByNameWhenNameInvalidThenReturnEmptyOptional(String name) {
        Optional<Role> roleUser = roleRepository.findByName(name);
        assertFalse(roleUser.isPresent());
    }

}
