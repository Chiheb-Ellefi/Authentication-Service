package delivery.system.authorizationservice.controllers;

import delivery.system.authorizationservice.models.request.AddAuthorityRequest;
import delivery.system.authorizationservice.models.response.AuthorityResponse;
import delivery.system.authorizationservice.services.AuthorityService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/authorities")
@RequiredArgsConstructor
public class AuthorityController {
    private final AuthorityService authorityService;
    @PostMapping
    public ResponseEntity<AuthorityResponse> addAuthority(@RequestBody @Valid AddAuthorityRequest request) {
       AuthorityResponse response= authorityService.addAuthority(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @DeleteMapping("/{name}")
    public ResponseEntity<Void> deleteAuthority(@PathVariable String name) {
        authorityService.deleteAuthorityByName(name);
        return ResponseEntity.noContent().build();
    }
}
