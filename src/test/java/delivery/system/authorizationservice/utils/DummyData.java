package delivery.system.authorizationservice.utils;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.repositories.AuthorityRepository;
import delivery.system.authorizationservice.repositories.RoleRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.List;


@RequiredArgsConstructor
@TestComponent
public class DummyData {
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final AuthorityRepository authorityRepository;




    public void initializeRolesAndAuthorities() {

        Authority readAuth = authorityRepository.findByName("read")
                .orElseGet(() -> authorityRepository.save(Authority.builder().name("read").build()));

        Authority writeAuth = authorityRepository.findByName("write")
                .orElseGet(() -> authorityRepository.save(Authority.builder().name("write").build()));

        Authority deleteAuth = authorityRepository.findByName("delete")
                .orElseGet(() -> authorityRepository.save(Authority.builder().name("delete").build()));

        Authority editAuth = authorityRepository.findByName("edit")
                .orElseGet(() -> authorityRepository.save(Authority.builder().name("edit").build()));

        roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(Role.builder()
                        .name("ROLE_USER")
                        .authorities(new HashSet<>(List.of(readAuth, writeAuth)))
                        .build()));

        roleRepository.findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(Role.builder()
                        .name("ROLE_ADMIN")
                        .authorities(new HashSet<>(List.of(readAuth, writeAuth, deleteAuth, editAuth)))
                        .build()));
    }

    public User getUser() {
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not initialized"));

        return User.builder()
                .username("test-user")
                .password(passwordEncoder.encode("test-password"))
                .roles(new HashSet<>(List.of(userRole)))
                .build();
    }


}