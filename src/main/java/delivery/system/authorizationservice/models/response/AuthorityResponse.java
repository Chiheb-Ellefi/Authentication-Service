package delivery.system.authorizationservice.models.response;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

@Getter
@Builder
@ToString
public class AuthorityResponse {
    private Long id;
    private String name;

}
