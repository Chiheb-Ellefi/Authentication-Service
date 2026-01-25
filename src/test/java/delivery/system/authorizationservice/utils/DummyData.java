package delivery.system.authorizationservice.utils;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.repositories.AuthorityRepository;
import delivery.system.authorizationservice.repositories.RoleRepository;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.List;

public class DummyData {
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final AuthorityRepository authorityRepository;


    public DummyData(PasswordEncoder passwordEncoder,
                     RoleRepository roleRepository,
                     AuthorityRepository authorityRepository) {
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.authorityRepository = authorityRepository;
    }

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

    public User getFirstUser() {
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not initialized"));

        return User.builder()
                .username("test-user")
                .password(passwordEncoder.encode("test-password"))
                .roles(new HashSet<>(List.of(userRole)))
                .build();
    }

    public User getSecondUser() {
        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN not initialized"));

        return User.builder()
                .username("test-admin")
                .password(passwordEncoder.encode("test-password"))
                .roles(new HashSet<>(List.of(adminRole)))
                .build();
    }
}