package delivery.system.authorizationservice.annotations;

import delivery.system.authorizationservice.annotations.validators.GrantTypesValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Constraint(validatedBy = GrantTypesValidator.class)
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidGrantTypes {
    String message() default "Invalid grant type provided";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}