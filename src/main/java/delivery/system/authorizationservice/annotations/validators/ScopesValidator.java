package delivery.system.authorizationservice.annotations.validators;

import delivery.system.authorizationservice.annotations.ValidScopes;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import org.springframework.beans.factory.annotation.Value;

import java.util.Set;
import java.util.stream.Collectors;

public class ScopesValidator implements ConstraintValidator<ValidScopes, Set<String>> {
    @Value("${auth.allowed-scopes}")
    private Set<String> ALLOWED;
    @Override
    public boolean isValid(Set<String> values, ConstraintValidatorContext context) {
        if (values == null || values.isEmpty()) return false;

        Set<String> invalid = values.stream()
                .filter(v -> !ALLOWED.contains(v))
                .collect(Collectors.toSet());

        if (!invalid.isEmpty()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                    "Invalid scopes: " + invalid + ". Allowed: " + ALLOWED
            ).addConstraintViolation();
            return false;
        }
        return true;
    }
}
