package delivery.system.authorizationservice.services;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {


    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public void save(OAuth2Authorization authorization) {
       log.info("Saving authorization: {}", authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
       log.info("Removing authorization: {}", authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        log.info("Finding authorization by id: {}", id);
        return null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        log.info("Finding authorization by token: {}", token);
       return null;
    }
}