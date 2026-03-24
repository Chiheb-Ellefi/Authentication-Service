package delivery.system.authorizationservice.exceptions;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Builder
@Setter
public class ErrorDetails {
    private  String message;
    private  String details;
}
