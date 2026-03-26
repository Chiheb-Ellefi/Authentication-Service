package delivery.system.authorizationservice.models.response;


import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ClientOperationResponse {
    private String message;
    private String clientId;
}