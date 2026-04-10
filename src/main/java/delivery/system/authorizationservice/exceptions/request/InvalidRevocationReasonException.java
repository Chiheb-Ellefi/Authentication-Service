package delivery.system.authorizationservice.exceptions.request;

public class InvalidRevocationReasonException extends RuntimeException {
    public InvalidRevocationReasonException(String message) {
        super(message);
    }
}
