package delivery.system.authorizationservice.models.response;

import lombok.Builder;
import lombok.Getter;

import java.util.Set;

@Builder
@Getter
public class ClientDetailsResponse {
    private String clientId;
    private String clientName;
    private Set<String> scopes;
    private Set<String> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> postLogoutRedirectUris;
}
