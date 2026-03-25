package delivery.system.authorizationservice.models.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;


@Getter
public class UpdateUserRequest {
    @NotNull
    private Long id;
    @NotBlank
    private String username;
}