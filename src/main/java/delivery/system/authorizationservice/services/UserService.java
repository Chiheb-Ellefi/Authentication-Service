package delivery.system.authorizationservice.services;

import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.exceptions.user.UserAlreadyExistsException;
import delivery.system.authorizationservice.models.CustomUserDetails;
import delivery.system.authorizationservice.models.request.AddUserRequest;
import delivery.system.authorizationservice.models.request.UpdateUserRequest;
import delivery.system.authorizationservice.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {
    private final CustomUserManager userManager;
    private final RoleService roleService;
    private final UserRepository userRepository;



    public void createUser(AddUserRequest request) {
        if (userManager.userExists(request.getUsername())) {
            throw new UserAlreadyExistsException("Username taken: " + request.getUsername());
        }

        CustomUserDetails userDetails = CustomUserDetails.builder()
                .username(request.getUsername())
                .password(request.getPassword())
                .authorities(Set.of())
                .enabled(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .build();
        userManager.createUser(userDetails);

            Set<Role> roles = request.getRoles().stream()
                    .map(roleService::findByName)
                    .collect(Collectors.toSet());
            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found after creation"));
            user.setRoles(roles);
            userRepository.save(user);

    }
    public void updateUser(UpdateUserRequest request) {
        CustomUserDetails userDetails = CustomUserDetails.builder()
                .id(request.getId())
                .username(request.getUsername())
                .authorities(Set.of())
                .enabled(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .build();
        userManager.updateUser(userDetails);
    }
    public void assignRoles(String username, Set<String> roleNames) {
        Set<Role> roles = roleNames.stream()
                .map(roleService::findByName)
                .collect(Collectors.toSet());

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        user.setRoles(roles);
        userRepository.save(user);
    }
}
