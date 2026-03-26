package delivery.system.authorizationservice.annotations.validators;

import delivery.system.authorizationservice.annotations.ValidRedirectUris;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class RedirectUrisValidator implements ConstraintValidator<ValidRedirectUris, Set<String>> {


    private static final Pattern URI_PATTERN = Pattern.compile(
            "^(https://[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?" +
                    "(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*" +
                    "(:[0-9]{1,5})?(/[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?" +
                    "|http://localhost(:[0-9]{1,5})?(/[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]*)?)$"
    );

    @Override
    public boolean isValid(Set<String> values, ConstraintValidatorContext context) {
        if (values == null || values.isEmpty()) return false;

        Set<String> invalid = values.stream()
                .filter(uri -> !isValidUri(uri))
                .collect(Collectors.toSet());

        if (!invalid.isEmpty()) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                    "Invalid redirect URIs: " + invalid + ". Must be https:// or http://localhost"
            ).addConstraintViolation();
            return false;
        }
        return true;
    }

    private boolean isValidUri(String uri) {
        if (uri == null || uri.isBlank()) return false;
        return URI_PATTERN.matcher(uri).matches();
    }
}