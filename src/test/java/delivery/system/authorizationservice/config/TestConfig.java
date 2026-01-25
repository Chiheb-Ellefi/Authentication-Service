package delivery.system.authorizationservice.config;

import delivery.system.authorizationservice.repositories.AuthorityRepository;
import delivery.system.authorizationservice.repositories.RoleRepository;
import delivery.system.authorizationservice.utils.DummyData;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@TestConfiguration
public class TestConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public DummyData dummyData(
            PasswordEncoder passwordEncoder,
            RoleRepository roleRepository,
            AuthorityRepository authorityRepository
    ) {
        return new DummyData(passwordEncoder, roleRepository, authorityRepository);
    }

}
