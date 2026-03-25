    package delivery.system.authorizationservice.services;


    import delivery.system.authorizationservice.entities.User;
    import delivery.system.authorizationservice.models.CustomUserDetails;
    import delivery.system.authorizationservice.repositories.UserRepository;
    import lombok.RequiredArgsConstructor;
    import org.jspecify.annotations.Nullable;
    import org.springframework.security.authentication.BadCredentialsException;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    import org.springframework.security.crypto.password.PasswordEncoder;
    import org.springframework.security.provisioning.UserDetailsManager;
    import org.springframework.stereotype.Service;

    import java.time.LocalDateTime;
    import java.util.Set;
    import java.util.stream.Collectors;

    @Service
    @RequiredArgsConstructor
    public class CustomUserManager implements UserDetailsManager {
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;

        @Override
        public void createUser(@Nullable UserDetails userDetails) {
            if (userDetails == null) throw new IllegalArgumentException("User cannot be null");



            User user = User.builder()
                    .username(userDetails.getUsername())
                    .password(passwordEncoder.encode(userDetails.getPassword()))
                    .enabled(userDetails.isEnabled())
                    .accountNonExpired(userDetails.isAccountNonExpired())
                    .accountNonLocked(userDetails.isAccountNonLocked())
                    .credentialsNonExpired(userDetails.isCredentialsNonExpired())
                    .build();

            userRepository.save(user);
        }

        @Override
        public void updateUser(@Nullable UserDetails userDetails) {
            if (userDetails == null) throw new IllegalArgumentException("User cannot be null");
            if(userDetails instanceof CustomUserDetails cd){
                User user = userRepository.findById(cd.getId())
                        .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userDetails.getUsername()));

                user.setUsername(userDetails.getUsername());
                userRepository.save(user);
            }


        }

        @Override
        public void deleteUser(@Nullable String username) {
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Username cannot be null or blank");
            }
            userRepository.deleteByUsername(username);
        }

        @Override
        public void changePassword(@Nullable String oldPassword, @Nullable String newPassword) {
            if (oldPassword == null || oldPassword.isBlank() ||
                    newPassword == null || newPassword.isBlank()) {
                throw new IllegalArgumentException("Passwords cannot be null or blank");
            }

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null) {
                throw new IllegalStateException("No authenticated user found");
            }

            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

            if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
                throw new BadCredentialsException("Old password is incorrect");
            }

            user.setPassword(passwordEncoder.encode(newPassword));
            user.setPasswordChangedAt(LocalDateTime.now());
            userRepository.save(user);
        }

        @Override
        public boolean userExists(@Nullable String username) {
            if (username == null || username.isBlank()) {
                return false;
            }
            return userRepository.existsByUsername(username);
        }

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
                        auths.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
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
        public void  enableAccount(String username ){
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            user.setEnabled(true);
            userRepository.save(user);
        }
        public void  disableAccount(String username ){
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            user.setEnabled(false);
            userRepository.save(user);
        }
        public void expireAccount(String username ){
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            user.setAccountNonExpired(false);
            userRepository.save(user);
        }
        public void unExpireAccount(String username ){
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            user.setAccountNonExpired(true);
            userRepository.save(user);
        }
        public void lockAccount(String username){
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            user.setAccountNonLocked(false);
            user.setLockedAt(LocalDateTime.now());
            userRepository.save(user);
        }
        public void unlockAccount(String username){
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            user.setAccountNonLocked(true);
            user.setLockedAt(null);
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
        }

        public void incrementFailedLoginAttempts(String username){
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            Integer attempts = user.getFailedLoginAttempts();
            user.setFailedLoginAttempts(attempts == null ? 1 : attempts + 1);
            userRepository.save(user);
        }
        public void resetFailedLoginAttempts(String username){
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            user.setFailedLoginAttempts(0);
            userRepository.save(user);
        }

    }