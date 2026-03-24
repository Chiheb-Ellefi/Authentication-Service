package delivery.system.authorizationservice.controllers;


import delivery.system.authorizationservice.models.request.AddRoleRequest;
import delivery.system.authorizationservice.models.response.RoleResponse;
import delivery.system.authorizationservice.services.RoleService;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/roles")
public class RoleController {
    private final RoleService roleService;

    @PostMapping
    public ResponseEntity<RoleResponse> addRole(@RequestBody @Valid AddRoleRequest request) {
        RoleResponse response = roleService.addRole(request);
        return ResponseEntity.ok(response);
    }
    @DeleteMapping("/{name}")
    public ResponseEntity<Void> deleteRole(@PathVariable String name) {
        roleService.deleteRoleByName(name);
        return ResponseEntity.noContent().build();
    }
}
