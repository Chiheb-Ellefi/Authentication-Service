package delivery.system.authorizationservice.models.response;

import lombok.Builder;
import lombok.Getter;
@Getter
@Builder
public class AuthorityResponse {
    private Long id;
    private String name;

}
