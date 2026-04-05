package delivery.system.authorizationservice.services;

import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.exceptions.user.PasswordDoNotMatchException;
import delivery.system.authorizationservice.exceptions.user.UserAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.user.UserNotFoundException;
import delivery.system.authorizationservice.models.request.AddUserRequest;
import delivery.system.authorizationservice.models.request.AssignRolesRequest;
import delivery.system.authorizationservice.models.request.ChangePasswordRequest;
import delivery.system.authorizationservice.models.request.UpdateUsernameRequest;
import delivery.system.authorizationservice.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {
    private final RoleService roleService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void createUser(AddUserRequest request) {
        saveUser(request);
    }
    @Transactional
    public void registerUser(AddUserRequest request) {
        request.setRoles(List.of("USER"));
        saveUser(request);
    }

    private void saveUser(AddUserRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username taken: " + request.getUsername());
        }
        Set<Role> roles = request.getRoles().stream()
                .map(roleName-> roleService.findByName(roleName.toUpperCase()))
                .collect(Collectors.toSet());
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(true)
                .roles(roles)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();
        userRepository.save(user);
    }

    @Transactional
    public void updateUsername(UpdateUsernameRequest request) {
        User user = getUserOrThrow(request.getId());
        if (!user.getUsername().equals(request.getUsername()) && userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username taken: " + request.getUsername());
        }
        user.setUsername(request.getUsername());

    }

    @Transactional
    public void deleteUser(Long id) {
        User user = getUserOrThrow(id);
        userRepository.delete(user);
    }


    @Transactional
    public void changePassword(ChangePasswordRequest request) {
        User user = getUserOrThrow(request.getId());
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new PasswordDoNotMatchException("Old password is incorrect");
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
    }

    public boolean userExists(Long id) {
        return userRepository.existsById(id);
    }

    @Transactional
    public void assignRoles(AssignRolesRequest request) {
        User user = getUserWithRolesOrThrow(request.getId());
        Set<Role> newRoles = request.getRoleNames().stream()
                .map(roleName->roleService.findByName(roleName.toUpperCase()))
                .collect(Collectors.toSet());

        Set<Role> mergedRoles = new HashSet<>(user.getRoles());
        mergedRoles.addAll(newRoles);
        user.setRoles(mergedRoles);


    }

    @Transactional
    public void replaceRoles(AssignRolesRequest request) {
        User user = getUserWithRolesOrThrow(request.getId());
        Set<Role> roles = request.getRoleNames().stream()
                .map(roleName->roleService.findByName(roleName.toUpperCase()))
                .collect(Collectors.toSet());

        user.setRoles(roles);
    }

    @Transactional
    public void removeRoles(AssignRolesRequest request) {
        User user = getUserWithRolesOrThrow(request.getId());
        Set<Role> rolesToRemove = request.getRoleNames().stream()
                .map(roleName->roleService.findByName(roleName.toUpperCase()))
                .collect(Collectors.toSet());
        user.getRoles().removeAll(rolesToRemove);
    }
    @Transactional
    public void enableAccount(Long id) {
        User user = getUserOrThrow(id);
        user.enable();
    }
    @Transactional
    public void disableAccount(Long id) {
        User user = getUserOrThrow(id);
        user.disable();
    }
    @Transactional
    public void expireAccount(Long id) {
        User user = getUserOrThrow(id);
        user.expire();
    }
    @Transactional
    public void unExpireAccount(Long id) {
        User user = getUserOrThrow(id);
        user.unexpire();
    }
    @Transactional
    public void lockAccount(Long id) {
        User user = getUserOrThrow(id);
        user.lock();
    }
    @Transactional
    public void unlockAccount(Long id) {
        User user = getUserOrThrow(id);
        user.unlock();
    }
    @Transactional
    public void incrementFailedLoginAttempts(Long id) {
        User user = getUserOrThrow(id);
        user.loginFailed();
    }
    @Transactional
    public void loggedIn(Long id) {
        User user = getUserOrThrow(id);
        user.loginSucceed();
    }

    private User getUserOrThrow(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
    }
    private User getUserWithRolesOrThrow(Long id) {
        return userRepository.findByIdWithRoles(id)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
    }
}
