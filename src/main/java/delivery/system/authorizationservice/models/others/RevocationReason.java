package delivery.system.authorizationservice.models.others;

import delivery.system.authorizationservice.exceptions.request.InvalidRevocationReasonException;
import delivery.system.authorizationservice.utils.RevocationReasonDeserializer;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import tools.jackson.databind.annotation.JsonDeserialize;

import java.util.Arrays;
@RequiredArgsConstructor
@Getter
@JsonDeserialize(using = RevocationReasonDeserializer.class)
public enum RevocationReason {
    USER_LOGOUT("USER_LOGOUT"),
    PASSWORD_CHANGE("PASSWORD_CHANGE"),
    ADMIN_REVOKE("ADMIN_REVOKE"),
    SUSPICIOUS_ACTIVITY("SUSPICIOUS_ACTIVITY");

    private final String value;

    public static RevocationReason fromString(String value) {
        return Arrays.stream(values())
                .filter(r -> r.value.equalsIgnoreCase(value))
                .findFirst()
                .orElseThrow(() -> new InvalidRevocationReasonException(
                        "Invalid reason: '" + value + "'. Valid values: " +
                                Arrays.stream(values()).map(RevocationReason::getValue).toList()
                ));
    }}