package delivery.system.authorizationservice.services;


import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.exceptions.authority.AuthorityAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.authority.AuthorityNotFoundException;
import delivery.system.authorizationservice.models.request.AddAuthorityRequest;
import delivery.system.authorizationservice.models.response.AuthorityResponse;
import delivery.system.authorizationservice.repositories.AuthorityRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
public class AuthorityServiceTest {

    @Mock
    private AuthorityRepository authorityRepository;
    @InjectMocks
    AuthorityService authorityService;


    /*------------findAuthorityTests-------------*/
    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("Should throw IllegalArgumentException when the authority name is invalid")
    public void findAuthorityByName_NameInvalid_ThrowsIllegalArgumentException(String name) {
        assertThrows(IllegalArgumentException.class,()->authorityService.findAuthorityByName(name),"authorityName is null or empty");
        verify(authorityRepository,never()).findByName(anyString());
    }

    @Test
    @DisplayName("Should return authority when authority name exists")
    public void findAuthorityByName_AuthorityExists_ReturnsAuthority() {

        Authority  authority = Authority.builder().id(1L).name("read").build();
        when(authorityRepository.findByName(authority.getName())).thenReturn(Optional.of(authority));
        Authority actual = authorityService.findAuthorityByName(authority.getName());
        assertNotNull(actual);
        assertEquals(authority.getName(),actual.getName());
        verify(authorityRepository).findByName(authority.getName());
    }
    @Test
    @DisplayName("Should throw AuthorityNotFoundException when auhtorityName does not exist ")
    public void findAuthorityByName_AuthorityNotFound_ThrowsAuthorityNotFoundException() {
        when(authorityRepository.findByName("read")).thenReturn(Optional.empty());
        assertThrows(AuthorityNotFoundException.class,()->authorityService.findAuthorityByName("read"));
        verify(authorityRepository).findByName("read");
    }

    /*------------addAuthorityTests-------------*/


    @Test
    @DisplayName("Should Throws AuthorityAlreadyExistsException when authority already exists")
    public void addAuthority_AuthorityAlreadyExists_ThrowsAuthorityAlreadyExistsException() {
        AddAuthorityRequest addAuthorityRequest = new AddAuthorityRequest("read");
        when(authorityRepository.findByName(addAuthorityRequest.getName())).thenReturn(Optional.of(Authority.builder().id(1L).name("read").build()));
        assertThrows(AuthorityAlreadyExistsException.class,()->authorityService.addAuthority(addAuthorityRequest));
        verify(authorityRepository,never()).save(any(Authority.class));
    }
    @Test
    @DisplayName("Should return AuthorityResponse when saved authority")
    public void addAuthority_AuthoritySaved_ReturnsAuthorityResponse() {
        AddAuthorityRequest addAuthorityRequest = new AddAuthorityRequest("read");
        Authority authority = Authority.builder().id(1L).name("read").build();
        AuthorityResponse expectedResponse = AuthorityResponse.builder().id(1L).name("read").build();
        when(authorityRepository.findByName(addAuthorityRequest.getName())).thenReturn(Optional.empty());
        when(authorityRepository.save(any(Authority.class))).thenReturn(authority);
        AuthorityResponse actualResponse = authorityService.addAuthority(addAuthorityRequest);
        assertEquals(expectedResponse.getId(),actualResponse.getId());
        assertEquals(expectedResponse.getName(),actualResponse.getName());
    }
    @Test
    @DisplayName("Should normalize name and return AuthorityResponse when authority is saved")
    public void addAuthority_NameNormalized_ReturnsAuthorityResponse() {
        AddAuthorityRequest addAuthorityRequest = new AddAuthorityRequest("  READ  ");
        Authority authority = Authority.builder().id(1L).name("read").build();
        AuthorityResponse expectedResponse = AuthorityResponse.builder().id(1L).name("read").build();
        when(authorityRepository.findByName("read")).thenReturn(Optional.empty());
        when(authorityRepository.save(any(Authority.class))).thenReturn(authority);
        AuthorityResponse actualResponse = authorityService.addAuthority(addAuthorityRequest);
        assertEquals(expectedResponse.getId(), actualResponse.getId());
        assertEquals(expectedResponse.getName(), actualResponse.getName());
        verify(authorityRepository).findByName("read");
        verify(authorityRepository).save(any(Authority.class));
    }

    /*------------deleteAuthorityByNameTests-------------*/
    @ParameterizedTest
    @NullAndEmptySource
    @DisplayName("Should throw IllegalArgumentException when authorityName is null or empty")
    public void deleteAuthorityByName_AuthorityNameIsInvalid_ThrowsIllegalArgumentException(String authorityName) {
        assertThrows(IllegalArgumentException.class, () -> authorityService.deleteAuthorityByName(authorityName));
        verify(authorityRepository, never()).findByName(anyString());
        verify(authorityRepository, never()).deleteByName(anyString());
    }
    @Test
    @DisplayName("Should throw AuthorityNotFoundException when authority not found")
    public void deleteAuthority_AuthorityNotFound_ThrowsAuthorityNotFoundException() {
        when(authorityRepository.findByName("read")).thenReturn(Optional.empty());
        assertThrows(AuthorityNotFoundException.class,()->authorityService.deleteAuthorityByName("read"));
        verify(authorityRepository,never()).deleteByName(anyString());
    }

    @Test
    @DisplayName("Should delete authority when authority is found")
    public void deleteAuthority_AuthorityExists_DeletesAuthority() {
        Authority authority = Authority.builder().id(1L).name("read").build();
        when(authorityRepository.findByName(authority.getName())).thenReturn(Optional.of(authority));
        authorityService.deleteAuthorityByName(authority.getName());
        verify(authorityRepository).deleteByName(authority.getName());
    }
}
