package delivery.system.authorizationservice.models.request;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;

import java.util.List;

@Getter
public class AddUserRequest {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
    @NotEmpty
    private List<String> roles;
}
