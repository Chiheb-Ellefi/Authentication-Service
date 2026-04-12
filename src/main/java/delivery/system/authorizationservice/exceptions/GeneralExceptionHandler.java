package delivery.system.authorizationservice.exceptions;

import delivery.system.authorizationservice.exceptions.authority.AuthorityAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.authority.AuthorityNotFoundException;
import delivery.system.authorizationservice.exceptions.client.ClientAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.client.ClientNotFoundException;
import delivery.system.authorizationservice.exceptions.request.BadRequestException;
import delivery.system.authorizationservice.exceptions.request.InvalidRevocationReasonException;
import delivery.system.authorizationservice.exceptions.request.TokenRevocationException;
import delivery.system.authorizationservice.exceptions.request.TokenRevokedException;
import delivery.system.authorizationservice.exceptions.role.RoleAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.role.RoleNotFoundException;
import delivery.system.authorizationservice.exceptions.user.PasswordDoNotMatchException;
import delivery.system.authorizationservice.exceptions.user.UserAlreadyExistsException;
import delivery.system.authorizationservice.exceptions.user.UserNotFoundException;
import delivery.system.authorizationservice.models.others.RevocationReason;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Arrays;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GeneralExceptionHandler {
    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorDetails> handleBadRequestException(BadRequestException e) {
        ErrorDetails errorDetails = ErrorDetails.builder()
                .message("Bad Request")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }
    @ExceptionHandler(AuthorityNotFoundException.class)
    public ResponseEntity<ErrorDetails> handleAuthorityNotFoundException(AuthorityNotFoundException e) {
        ErrorDetails errorDetails=ErrorDetails.builder()
                .message("Authority not found")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }
    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ErrorDetails> handleRoleNotFoundException(RoleNotFoundException e) {
        ErrorDetails errorDetails=ErrorDetails.builder()
                .message("Role not found")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorDetails> handleValidationException(MethodArgumentNotValidException e) {
        String details = e.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .collect(Collectors.joining(", "));
        ErrorDetails error = ErrorDetails.builder()
                .message("Validation failed")
                .details(details)
                .build();
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }
    @ExceptionHandler(AuthorityAlreadyExistsException.class)
    public ResponseEntity<ErrorDetails> handleAuthorityAlreadyExists(AuthorityAlreadyExistsException e) {
        ErrorDetails error = ErrorDetails.builder()
                .message("Conflict - Authority already exists")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(error, HttpStatus.CONFLICT);
    }
    @ExceptionHandler(RoleAlreadyExistsException.class)
    public ResponseEntity<ErrorDetails> handleRoleAlreadyExists(RoleAlreadyExistsException e) {
        ErrorDetails error = ErrorDetails.builder()
                .message("Conflict - Role already exists")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(error, HttpStatus.CONFLICT);
    }
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorDetails> handleUserAlreadyExists(UserAlreadyExistsException e) {
        ErrorDetails errorDetails=ErrorDetails.builder()
                .message("Conflict - Username already exists")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.CONFLICT);
    }
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorDetails> handleUserNotFoundException(UserNotFoundException e) {
        ErrorDetails errorDetails=ErrorDetails.builder()
                .message("User not found")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }
    @ExceptionHandler(PasswordDoNotMatchException.class)
    public ResponseEntity<ErrorDetails> handlePasswordDoNotMatchException(PasswordDoNotMatchException e) {
        ErrorDetails errorDetails=ErrorDetails.builder()
                .message("Password do not match")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }
@ExceptionHandler(ClientAlreadyExistsException.class)
    public ResponseEntity<ErrorDetails> handleClientAlreadyExists(ClientAlreadyExistsException e) {
        ErrorDetails errorDetails =ErrorDetails.builder()
                .message("Conflict - Client already exists")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.CONFLICT);
}
@ExceptionHandler(ClientNotFoundException.class)
    public ResponseEntity<ErrorDetails> handleClientNotFoundException(ClientNotFoundException e) {
        ErrorDetails errorDetails=  ErrorDetails.builder()
                .message("Client not found")
                .details(e.getMessage())
                .build();

        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
}

    @ExceptionHandler(InvalidRevocationReasonException.class)
    public ResponseEntity<ErrorDetails> handleInvalidRevocationReasonException(InvalidRevocationReasonException e) {
        ErrorDetails errorDetails=  ErrorDetails.builder()
                .message("INVALID_REVOCATION_REASON: "+e.getMessage())
                .details(Arrays.stream(RevocationReason.values()).map(RevocationReason::getValue).toList().toString())
                .build();

        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }
    @ExceptionHandler(TokenRevocationException.class)
    public  ResponseEntity<ErrorDetails> handleTokenRevocationException(TokenRevocationException e) {

        ErrorDetails errorDetails=ErrorDetails.builder()
                .message(e.getMessage())
                .details(e.getCause().getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    @ExceptionHandler(TokenRevokedException.class)
    public ResponseEntity<ErrorDetails> handleTokenRevokedException(TokenRevokedException e) {
        ErrorDetails errorDetails=ErrorDetails.builder()
                .message("Token revoked")
                .details(e.getMessage())
                .build();
        return new ResponseEntity<>(errorDetails, HttpStatus.UNAUTHORIZED);
    }


}
