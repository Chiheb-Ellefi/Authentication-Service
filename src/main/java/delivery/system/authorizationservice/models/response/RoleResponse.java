package delivery.system.authorizationservice.models.response;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.Set;

@Getter
@Builder
@ToString
public class RoleResponse {
    private Long id;
    private String name;
    private Set<String> authorities;
}