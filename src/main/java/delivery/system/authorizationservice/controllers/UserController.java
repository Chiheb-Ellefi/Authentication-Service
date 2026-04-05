package delivery.system.authorizationservice.controllers;

import delivery.system.authorizationservice.models.request.AddUserRequest;
import delivery.system.authorizationservice.services.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/users")
public class UserController {
    private final UserService userService;

    @PostMapping
    public ResponseEntity<String> addUser(@RequestBody @Valid AddUserRequest request) {
        userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("User created successfully");
    }
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody @Valid AddUserRequest request) {
       userService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

}
