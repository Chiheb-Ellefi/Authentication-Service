package delivery.system.authorizationservice.utils;

import java.security.SecureRandom;
import java.util.Base64;

public class ClientHelperMethods {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Base64.Encoder BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding();

    public static String generateClientId(String clientName) {
        byte[] randomBytes = new byte[16];
        SECURE_RANDOM.nextBytes(randomBytes);
        String randomPart = BASE64_ENCODER.encodeToString(randomBytes);
        String sanitizedName = clientName.toLowerCase()
                .replaceAll("[^a-z0-9]", "-")
                .replaceAll("-+", "-")
                .replaceAll("^-|-$", "");
        return sanitizedName + "-" + randomPart;
    }


    public static String generateClientSecret() {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return BASE64_ENCODER.encodeToString(randomBytes);
    }
}