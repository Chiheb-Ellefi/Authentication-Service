package delivery.system.authorizationservice.exceptions.request;

public class TokenRevokedException extends RuntimeException {
    public TokenRevokedException(String message) {
        super(message);
    }
}
