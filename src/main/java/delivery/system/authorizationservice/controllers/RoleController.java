package delivery.system.authorizationservice.controllers;


import delivery.system.authorizationservice.models.request.AddRoleRequest;
import delivery.system.authorizationservice.models.response.RoleResponse;
import delivery.system.authorizationservice.services.RoleService;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/roles")
public class RoleController {
    private final RoleService roleService;

    @GetMapping
    public ResponseEntity<List<RoleResponse>> getAllRoles() {
        return ResponseEntity.ok(roleService.findAll());
    }

    @PostMapping
    public ResponseEntity<RoleResponse> addRole(@RequestBody @Valid AddRoleRequest request) {
        RoleResponse response = roleService.addRole(request);
  return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
    @DeleteMapping("/{name}")
    public ResponseEntity<Void> deleteRole(@PathVariable String name) {
        roleService.deleteRoleByName(name);
        return ResponseEntity.noContent().build();
    }
}
