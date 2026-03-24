package delivery.system.authorizationservice.models.response;

import lombok.Builder;
import lombok.Getter;

import java.util.Set;

@Getter
@Builder
public class RoleResponse {
    private Long id;
    private String name;
    private Set<String> authorities;
}