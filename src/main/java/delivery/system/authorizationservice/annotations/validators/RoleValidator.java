package delivery.system.authorizationservice.annotations.validators;

import delivery.system.authorizationservice.annotations.ValidRole;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Value;

import java.util.Set;

public class RoleValidator implements ConstraintValidator<ValidRole, String> {

    private static final String ROLE_PATTERN = "^[a-zA-Z]+$";

    @Override
    public boolean isValid(String role, ConstraintValidatorContext context) {
        if (role == null || role.isBlank()) return false;

        if (!role.matches(ROLE_PATTERN)) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                    "Invalid role: " + role + ". Only letters allowed, no spaces or special characters."
            ).addConstraintViolation();
            return false;
        }

        return true;
    }
}