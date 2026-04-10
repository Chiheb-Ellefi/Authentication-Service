package delivery.system.authorizationservice.exceptions.request;

public class TokenRevocationException extends  RuntimeException {
    public TokenRevocationException(String message, Throwable cause) {
        super(message,cause);
    }
}
