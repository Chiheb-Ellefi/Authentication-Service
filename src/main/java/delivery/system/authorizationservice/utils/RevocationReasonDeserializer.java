package delivery.system.authorizationservice.utils;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;
import delivery.system.authorizationservice.models.others.RevocationReason;

public class RevocationReasonDeserializer extends ValueDeserializer<RevocationReason> {

    @Override
    public RevocationReason deserialize(JsonParser p, DeserializationContext ctx) {
        String value = p.getString();
        return RevocationReason.fromString(value);
    }
}