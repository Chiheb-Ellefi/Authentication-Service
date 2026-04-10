package delivery.system.authorizationservice.services;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;

import delivery.system.authorizationservice.exceptions.role.RoleAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.role.RoleNotFoundException;
import delivery.system.authorizationservice.models.request.AddRoleRequest;
import delivery.system.authorizationservice.models.response.RoleResponse;
import delivery.system.authorizationservice.repositories.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;
    private final AuthorityService authorityService;

    public Role findByName(String name) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Role name cannot be null or blank");
        String normalizedName = "ROLE_"+name.toUpperCase();
        return roleRepository.findByName(normalizedName).orElseThrow(() -> new RoleNotFoundException("Role not found: "+name));
    }

    @Transactional
    public RoleResponse addRole(AddRoleRequest request) {
        String normalizedName = "ROLE_" + request.getName().trim().toUpperCase();
        if (roleRepository.findByName(normalizedName).isPresent())
            throw new RoleAlreadyExistsException("Role already exists: " + normalizedName);
        Set<Authority> authorities = request.getAuthorities().stream().map(name -> authorityService.findAuthorityByName(name.toLowerCase().trim())).collect(Collectors.toSet());
        Role saved = roleRepository.save(Role.builder().name(normalizedName).authorities(authorities).build());
        return RoleResponse.builder().id(saved.getId()).name(saved.getName()).authorities(authorities.stream().map(Authority::getName).collect(Collectors.toSet())).build();
    }

    @Transactional
    public void deleteRoleByName(String name) {
        if (name == null || name.isBlank())
            throw new IllegalArgumentException("roleName is null or empty");
        String normalizedName = "ROLE_"+name.toUpperCase();
        if (roleRepository.findByName(normalizedName).isEmpty())
            throw new RoleNotFoundException("Role not found: " + name);
         roleRepository.deleteByName(normalizedName);
    }

    public List<RoleResponse> findAll() {
       return roleRepository.findAllWithAuthorities().stream().map(role -> RoleResponse.builder()
               .id(role.getId())
               .name(role.getName())
               .authorities(role.getAuthorities().stream().map(Authority::getName).collect(Collectors.toSet())).build())
               .collect(Collectors.toList());
    }
}
/*

public List<RoleResponse> findAll() {
    return roleRepository.findAll().stream().map(role -> RoleResponse.builder()
            .id(role.getId())
            .name(role.getName())
            .authorities(role.getAuthorities().stream().map(Authority::getName).collect(Collectors.toSet())).build()).collect(Collectors.toList());
}
*/
