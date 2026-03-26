package delivery.system.authorizationservice.annotations.validators;

import delivery.system.authorizationservice.annotations.ValidGrantTypes;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Value;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;


public class GrantTypesValidator implements ConstraintValidator<ValidGrantTypes,  Set<String>> {
    @Value("${auth.allowed-grant-types}")
    private Set<String> ALLOWED;
    @Override
    public boolean isValid(Set<String> values, ConstraintValidatorContext context) {
        if (values == null || values.isEmpty()) return false;

        Set<String> invalid=values.stream().filter(grantType->!ALLOWED.contains(grantType)).collect(Collectors.toSet());
        if(!invalid.isEmpty()){
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate("Invalid grant-type(s): "+ invalid +". Must be: "+ Arrays.toString(ALLOWED.toArray())).addConstraintViolation();
            return false;
        }
        return true;
    }
}
