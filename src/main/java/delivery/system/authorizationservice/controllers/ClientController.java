package delivery.system.authorizationservice.controllers;

import delivery.system.authorizationservice.models.request.ClientRegistrationRequest;
import delivery.system.authorizationservice.models.response.ClientDetailsResponse;
import delivery.system.authorizationservice.models.response.ClientRegistrationResponse;
import delivery.system.authorizationservice.services.RegisteredClientService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/clients")
public class ClientController {
    private final RegisteredClientService registeredClientService;


    @PostMapping
    public ResponseEntity<ClientRegistrationResponse> registerClient(@RequestBody @Valid ClientRegistrationRequest request) {
        ClientRegistrationResponse clientRegistrationResponse = registeredClientService.registerClient(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(clientRegistrationResponse);
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<ClientDetailsResponse> getByClientId(@PathVariable @NotBlank String  clientId) {
        ClientDetailsResponse clientDetailsResponse = registeredClientService.getByClientId(clientId);
        return ResponseEntity.ok(clientDetailsResponse);
    }



}
