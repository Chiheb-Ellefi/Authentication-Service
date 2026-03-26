package delivery.system.authorizationservice.annotations;

import delivery.system.authorizationservice.annotations.validators.ScopesValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.FIELD})
@Constraint(validatedBy = ScopesValidator.class)
public @interface ValidScopes {
    String message() default "Invalid scope provided. Allowed: openid, profile, email, phone, address, read, write";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}