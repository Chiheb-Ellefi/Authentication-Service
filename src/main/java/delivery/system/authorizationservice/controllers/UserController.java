package delivery.system.authorizationservice.controllers;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.entities.User;
import delivery.system.authorizationservice.models.CustomUserDetails;
import delivery.system.authorizationservice.repositories.UserRepository;
import delivery.system.authorizationservice.services.CustomUserManager;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserRepository userRepository;
    private final CustomUserManager authenticationManager;


    @GetMapping
    public ResponseEntity<User> index() {
        Set<Role> roles = new HashSet<>();
        roles.add(Role.builder().name("ADMIN").build());
        User userDetails = User.builder()
                .username("admin")
                .password("admin")
                .build();

        authenticationManager.createUser(new CustomUserDetails(userDetails));
        return ResponseEntity.ok(userDetails);
    }
   @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("hello");
   }

}
