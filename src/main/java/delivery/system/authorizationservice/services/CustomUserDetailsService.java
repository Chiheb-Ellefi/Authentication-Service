    package delivery.system.authorizationservice.services;


    import delivery.system.authorizationservice.entities.User;

    import delivery.system.authorizationservice.models.others.CustomUserDetails;
    import delivery.system.authorizationservice.repositories.UserRepository;
    import lombok.RequiredArgsConstructor;
    import org.jspecify.annotations.Nullable;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;

    import org.springframework.stereotype.Service;

    import java.util.Set;
    import java.util.stream.Collectors;

    @Service
    @RequiredArgsConstructor
    public class CustomUserDetailsService implements UserDetailsService {
        private final UserRepository userRepository;


        @Override
        public @Nullable UserDetails loadUserByUsername(@Nullable String username)
                throws UsernameNotFoundException {
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Username cannot be null or blank");
            }
            User user = userRepository.findByUsernameWithRoles(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

            Set<GrantedAuthority> authorities = user.getRoles().stream()
                    .flatMap(role -> {
                        Set<GrantedAuthority> auths = role.getAuthorities().stream()
                                .map(a -> (GrantedAuthority) new SimpleGrantedAuthority(a.getName()))
                                .collect(Collectors.toSet());
                        auths.add(new SimpleGrantedAuthority(role.getName()));
                        return auths.stream();
                    })
                    .collect(Collectors.toSet());
            return CustomUserDetails.builder()
                    .id(user.getId())
                    .username(user.getUsername())
                    .password(user.getPassword())
                    .authorities(authorities)
                    .enabled(user.isEnabled())
                    .accountNonExpired(user.isAccountNonExpired())
                    .credentialsNonExpired(user.isCredentialsNonExpired())
                    .accountNonLocked(user.isAccountNonLocked())
                    .build();
        }


    }