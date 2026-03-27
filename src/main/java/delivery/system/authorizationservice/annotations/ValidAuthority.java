package delivery.system.authorizationservice.annotations;

import delivery.system.authorizationservice.annotations.validators.AuthorityValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target( ElementType.FIELD)
@Retention( RetentionPolicy.RUNTIME )
@Constraint(validatedBy = AuthorityValidator.class)
public @interface ValidAuthority {
    String message() default "Invalid authority provided.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
