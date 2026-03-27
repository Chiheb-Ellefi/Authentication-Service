package delivery.system.authorizationservice.annotations.validators;

import delivery.system.authorizationservice.annotations.ValidAuthority;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
public class AuthorityValidator implements ConstraintValidator<ValidAuthority, String> {

    private static final String AUTHORITY_PATTERN = "^[a-z]+:[a-z]+$";

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) return false;

        if (!value.matches(AUTHORITY_PATTERN)) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                    "Invalid authority: " + value + ". Expected format: resource:action (e.g., user:read)"
            ).addConstraintViolation();
            return false;
        }

        return true;
    }
}