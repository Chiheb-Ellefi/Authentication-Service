package delivery.system.authorizationservice.models.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import delivery.system.authorizationservice.annotations.ValidAuthority;
import jakarta.validation.constraints.NotBlank;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class AddAuthorityRequest {
    @JsonProperty("name")
    @NotBlank(message = "Authority name cannot be blank")
    @ValidAuthority
    private String name;
}
