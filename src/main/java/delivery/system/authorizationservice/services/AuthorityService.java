package delivery.system.authorizationservice.services;


import delivery.system.authorizationservice.entities.Authority;
import delivery.system.authorizationservice.exceptions.authority.AuthorityAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.authority.AuthorityNotFoundException;
import delivery.system.authorizationservice.models.request.AddAuthorityRequest;
import delivery.system.authorizationservice.models.response.AuthorityResponse;
import delivery.system.authorizationservice.repositories.AuthorityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class AuthorityService {
    private final AuthorityRepository authorityRepository;

    public Authority findAuthorityByName(String authorityName) {
        if (authorityName == null || authorityName.isBlank())
            throw new IllegalArgumentException("authorityName is null or empty");
        String normalized = authorityName.trim().toLowerCase();
        return authorityRepository.findByName(normalized).orElseThrow(() -> new AuthorityNotFoundException("Authority not found: " + authorityName));
    }

    @Transactional
    public AuthorityResponse addAuthority(AddAuthorityRequest addAuthorityRequest) {
        String  normalizedName = addAuthorityRequest.getName().trim().toLowerCase();
        if(authorityRepository.findByName(normalizedName).isPresent())    throw new AuthorityAlreadyExistsException("Authority already exists: " + normalizedName);
        Authority authority = Authority.builder().name(normalizedName).build();
        Authority savedAuthority = authorityRepository.save(authority);
        return AuthorityResponse.builder().id(savedAuthority.getId()).name(savedAuthority.getName()).build();
    }

    @Transactional
    public void deleteAuthorityByName(String authorityName) {
        if (authorityName == null || authorityName.isBlank())
            throw new IllegalArgumentException("authorityName is null or empty");
        String  normalizedName = authorityName.trim().toLowerCase();
        if (authorityRepository.findByName(normalizedName).isEmpty())
            throw new AuthorityNotFoundException("Authority not found: " + authorityName);
        authorityRepository.deleteByName(normalizedName);
    }
}
