package delivery.system.authorizationservice.models.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class UpdateUsernameRequest {
    @NotNull
    private Long id;
    @NotBlank
    private String username;
}