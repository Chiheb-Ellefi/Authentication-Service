package delivery.system.authorizationservice.exceptions.authority;

public class AuthorityAlreadyExistsException extends RuntimeException {
    public AuthorityAlreadyExistsException(String message) {
        super(message);
    }
}
