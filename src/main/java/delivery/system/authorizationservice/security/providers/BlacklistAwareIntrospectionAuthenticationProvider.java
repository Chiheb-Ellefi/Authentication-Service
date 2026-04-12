package delivery.system.authorizationservice.security.providers;


import delivery.system.authorizationservice.services.BlacklistService;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;

import java.util.Objects;

@RequiredArgsConstructor
public class BlacklistAwareIntrospectionAuthenticationProvider implements AuthenticationProvider {
    private final BlacklistService blacklistService;
    private final OAuth2TokenIntrospectionAuthenticationProvider delegate;
    @Override
    public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication auth = delegate.authenticate(authentication);
        if (auth == null) return null;
        OAuth2TokenIntrospectionAuthenticationToken token=(OAuth2TokenIntrospectionAuthenticationToken)auth;
        if (!token.getTokenClaims().isActive()) {
            return auth;
        }
        String jti = (String) token.getTokenClaims()
                .getClaims()
                .get(JwtClaimNames.JTI);
        if (jti != null && blacklistService.isAccessRevoked(jti)) {
           return buildInactiveResponse(token);
        }
        return  auth;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
    }
    private Authentication buildInactiveResponse(
            OAuth2TokenIntrospectionAuthenticationToken original) {


        OAuth2TokenIntrospection inactiveClaims = OAuth2TokenIntrospection.builder()
                .active(false)
                .build();

        return new OAuth2TokenIntrospectionAuthenticationToken(
                original.getToken(),
                (Authentication) Objects.requireNonNull(original.getPrincipal()),
                Objects.requireNonNull(original.getCredentials()).toString(),
                inactiveClaims.getClaims()
        );
    }
}
