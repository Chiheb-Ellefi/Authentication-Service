package delivery.system.authorizationservice.services;

import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.entities.Role;
import delivery.system.authorizationservice.exceptions.authority.AuthorityNotFoundException;
import delivery.system.authorizationservice.exceptions.role.RoleAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.role.RoleNotFoundException;
import delivery.system.authorizationservice.models.request.AddRoleRequest;
import delivery.system.authorizationservice.models.response.RoleResponse;
import delivery.system.authorizationservice.repositories.RoleRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class RoleServiceTest {

    @Mock
    private RoleRepository roleRepository;
    @Mock
    private AuthorityService authorityService;
    @InjectMocks
    private RoleService roleService;


    /*------------helpers-------------*/

    private AddRoleRequest buildRequest(String name, List<String> authorities) {
        AddRoleRequest request = mock(AddRoleRequest.class);
        when(request.getName()).thenReturn(name);
        if (authorities != null) when(request.getAuthorities()).thenReturn(authorities);
        return request;
    }

    private Authority buildAuthority(Long id, String name) {
        return Authority.builder().id(id).name(name).build();
    }

    private Role buildRole(Long id, String name, Set<Authority> authorities) {
        return Role.builder().id(id).name(name).authorities(authorities).build();
    }


    /*------------findByNameTests-------------*/

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    @DisplayName("Should throw IllegalArgumentException when role name is null, empty, or blank")
    public void findByName_NameInvalid_ThrowsIllegalArgumentException(String name) {
        assertThrows(IllegalArgumentException.class, () -> roleService.findByName(name));
        verify(roleRepository, never()).findByName(anyString());
    }

    @Test
    @DisplayName("Should return role when role name exists")
    public void findByName_RoleExists_ReturnsRole() {
        Role role = buildRole(1L, "ADMIN", Set.of());
        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.of(role));

        Role actual = roleService.findByName("ADMIN");

        assertNotNull(actual);
        assertEquals("ADMIN", actual.getName());
        verify(roleRepository).findByName("ROLE_ADMIN");
    }

    @Test
    @DisplayName("Should throw RoleNotFoundException when role name does not exist")
    public void findByName_RoleNotFound_ThrowsRoleNotFoundException() {
        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.empty());

        assertThrows(RoleNotFoundException.class, () -> roleService.findByName("ADMIN"));

        verify(roleRepository).findByName("ROLE_ADMIN");
    }


    /*------------addRoleTests-------------*/

    @Test
    @DisplayName("Should throw RoleAlreadyExistsException when role already exists")
    public void addRole_RoleAlreadyExists_ThrowsRoleAlreadyExistsException() {
        AddRoleRequest request = buildRequest("ADMIN", null);
        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.of(buildRole(1L, "ADMIN", Set.of())));

        assertThrows(RoleAlreadyExistsException.class, () -> roleService.addRole(request));

        verify(roleRepository, never()).save(any(Role.class));
        verify(authorityService, never()).findAuthorityByName(anyString());
    }

    @Test
    @DisplayName("Should save role with correct name and authorities and return mapped RoleResponse")
    public void addRole_RoleSaved_ReturnsRoleResponse() {
        Authority readAuthority = buildAuthority(1L, "read");
        Authority writeAuthority = buildAuthority(2L, "write");
        AddRoleRequest request = buildRequest("ADMIN", List.of("read", "write"));

        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.empty());
        when(authorityService.findAuthorityByName("read")).thenReturn(readAuthority);
        when(authorityService.findAuthorityByName("write")).thenReturn(writeAuthority);
        when(roleRepository.save(any(Role.class))).thenReturn(buildRole(1L, "ADMIN", Set.of(readAuthority, writeAuthority)));

        RoleResponse actual = roleService.addRole(request);

        // assert response mapping
        assertEquals(1L, actual.getId());
        assertEquals("ADMIN", actual.getName());
        assertEquals(Set.of("read", "write"), actual.getAuthorities());

        // assert what was actually passed to save
        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(captor.capture());
        Role capturedRole = captor.getValue();
        assertEquals("ROLE_ADMIN", capturedRole.getName());
        assertEquals(Set.of(readAuthority, writeAuthority), capturedRole.getAuthorities());
    }

    @Test
    @DisplayName("Should normalize role name to uppercase and trimmed before saving")
    public void addRole_RoleNameNormalized_SavesWithUppercaseName() {
        Authority readAuthority = buildAuthority(1L, "read");
        AddRoleRequest request = buildRequest("  admin  ", List.of("read"));

        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.empty());
        when(authorityService.findAuthorityByName("read")).thenReturn(readAuthority);
        when(roleRepository.save(any(Role.class))).thenReturn(buildRole(1L, "ADMIN", Set.of(readAuthority)));

        RoleResponse actual = roleService.addRole(request);

        assertEquals("ADMIN", actual.getName());
        verify(roleRepository).findByName("ROLE_ADMIN");

        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(captor.capture());
        assertEquals("ROLE_ADMIN", captor.getValue().getName());
    }

    @Test
    @DisplayName("Should normalize authority names to lowercase and trimmed before lookup")
    public void addRole_AuthorityNamesNormalized_LooksUpWithLowercaseName() {
        Authority readAuthority = buildAuthority(1L, "read");
        Authority writeAuthority = buildAuthority(2L, "write");
        AddRoleRequest request = buildRequest("ADMIN", List.of("  READ  ", "  WRITE  "));

        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.empty());
        when(authorityService.findAuthorityByName("read")).thenReturn(readAuthority);
        when(authorityService.findAuthorityByName("write")).thenReturn(writeAuthority);
        when(roleRepository.save(any(Role.class))).thenReturn(buildRole(1L, "ADMIN", Set.of(readAuthority, writeAuthority)));

        RoleResponse actual = roleService.addRole(request);

        verify(authorityService).findAuthorityByName("read");
        verify(authorityService).findAuthorityByName("write");

        assertEquals(Set.of("read", "write"), actual.getAuthorities());

        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository).save(captor.capture());
        assertEquals(Set.of(readAuthority, writeAuthority), captor.getValue().getAuthorities());
    }

    @Test
    @DisplayName("Should propagate AuthorityNotFoundException when an authority does not exist")
    public void addRole_AuthorityNotFound_ThrowsAuthorityNotFoundException() {
        AddRoleRequest request = buildRequest("ADMIN", List.of("nonexistent"));

        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.empty());
        when(authorityService.findAuthorityByName("nonexistent")).thenThrow(new AuthorityNotFoundException("Authority not found: nonexistent"));

        assertThrows(AuthorityNotFoundException.class, () -> roleService.addRole(request));

        verify(roleRepository, never()).save(any(Role.class));
    }


    /*------------deleteRoleByNameTests-------------*/

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    @DisplayName("Should throw IllegalArgumentException when role name is null, empty, or blank")
    public void deleteRoleByName_NameInvalid_ThrowsIllegalArgumentException(String name) {
        assertThrows(IllegalArgumentException.class, () -> roleService.deleteRoleByName(name));
        verify(roleRepository, never()).findByName(anyString());
        verify(roleRepository, never()).deleteByName(anyString());
    }

    @Test
    @DisplayName("Should throw RoleNotFoundException when role does not exist")
    public void deleteRoleByName_RoleNotFound_ThrowsRoleNotFoundException() {
        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.empty());

        assertThrows(RoleNotFoundException.class, () -> roleService.deleteRoleByName("ADMIN"));

        verify(roleRepository, never()).deleteByName(anyString());
    }

    @Test
    @DisplayName("Should delete role when role exists")
    public void deleteRoleByName_RoleExists_DeletesRole() {
        Role role = buildRole(1L, "ADMIN", Set.of());
        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.of(role));

        roleService.deleteRoleByName("ADMIN");

        verify(roleRepository).deleteByName("ROLE_ADMIN");
    }
}