package delivery.system.authorizationservice.annotations;

import delivery.system.authorizationservice.annotations.validators.RedirectUrisValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.FIELD})
@Constraint(validatedBy = RedirectUrisValidator.class)
public @interface ValidRedirectUris {
    String message() default "Redirect URIs must be https:// or http://localhost";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}