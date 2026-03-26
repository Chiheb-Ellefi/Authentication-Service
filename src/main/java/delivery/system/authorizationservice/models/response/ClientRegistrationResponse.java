package delivery.system.authorizationservice.models.response;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class ClientRegistrationResponse {
    private String clientId;
    private String clientSecret;
    private String clientName;
}
