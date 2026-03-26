package delivery.system.authorizationservice.models.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import delivery.system.authorizationservice.annotations.ValidGrantTypes;
import delivery.system.authorizationservice.annotations.ValidRedirectUris;
import delivery.system.authorizationservice.annotations.ValidScopes;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import lombok.Getter;


import java.util.Set;

@Getter
public class ClientRegistrationRequest {

    @NotBlank(message = "Client name is required")
    @JsonProperty("clientName")
    private String clientName;

    @NotEmpty(message = "At least one redirect URI is required")
    @ValidRedirectUris
    @JsonProperty("redirectUris")
    private Set<String> redirectUris;

    @NotEmpty(message = "At least one scope is required")
    @ValidScopes
    @JsonProperty("scopes")
    private Set<String> scopes;

    @NotEmpty(message = "At least one grant type is required")
    @ValidGrantTypes
    @JsonProperty("authorizationGrantTypes")
    private Set<String> authorizationGrantTypes;

    @NotBlank(message = "Post logout redirect URI is required")
    @org.hibernate.validator.constraints.URL(message = "Post logout redirect URI must be a valid URL")
    @JsonProperty("postLogoutRedirectUri")
    private String postLogoutRedirectUri;

}