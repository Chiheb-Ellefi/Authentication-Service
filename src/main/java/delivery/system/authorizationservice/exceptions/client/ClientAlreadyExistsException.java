package delivery.system.authorizationservice.exceptions.client;

public class ClientAlreadyExistsException extends RuntimeException
{
    public ClientAlreadyExistsException(String message)
    {
        super(message);
    }
}
