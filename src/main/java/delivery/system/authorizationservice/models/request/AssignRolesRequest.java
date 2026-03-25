package delivery.system.authorizationservice.models.request;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class AssignRolesRequest {
    @NonNull
    private Long id;
    @NotEmpty
    private List<String> roleNames;
}
