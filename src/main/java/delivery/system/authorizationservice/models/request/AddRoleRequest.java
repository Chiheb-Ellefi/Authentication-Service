package delivery.system.authorizationservice.models.request;


import com.fasterxml.jackson.annotation.JsonProperty;
import delivery.system.authorizationservice.annotations.ValidRole;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@NoArgsConstructor
@Setter
public class AddRoleRequest {
    @JsonProperty("name")
    @NotBlank(message = "Name cannot be blank")
    @ValidRole
    private String name;

    @JsonProperty("authorities")
    @NotEmpty(message = "Authorities cannot be empty")
    private List<@NotBlank String> authorities;
}