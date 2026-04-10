package delivery.system.authorizationservice.services;


import delivery.system.authorizationservice.exceptions.request.TokenRevocationException;
import delivery.system.authorizationservice.models.others.BlacklistedTokenMetadata;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;


import java.time.Duration;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class BlacklistService {
    @Value("${token.access-token-ttl}")
    private long ACCESS_TOKEN_TTL;
    @Value("${token.refresh-token-ttl}")
    private long REFRESH_TOKEN_TTL;

    private final RedisTemplate<String, BlacklistedTokenMetadata> template;

    private static final String ACCESS_PREFIX  = "blacklist:access:";
    private static final String REFRESH_PREFIX = "blacklist:refresh:";



    public void revokeAccessToken(String jti, BlacklistedTokenMetadata metadata) {
      store(ACCESS_PREFIX+jti,metadata,ACCESS_TOKEN_TTL);
    }
    public void revokeRefreshToken(String token,BlacklistedTokenMetadata metadata) {
        store(REFRESH_PREFIX+token,metadata,REFRESH_TOKEN_TTL);
    }

    public boolean isAccessRevoked(String jti) {
        return Boolean.TRUE.equals(template.hasKey(ACCESS_PREFIX + jti));
    }
    public boolean isRefreshRevoked(String token) {
        return Boolean.TRUE.equals(template.hasKey(REFRESH_PREFIX + token));
    }

    public Optional<BlacklistedTokenMetadata> getAccessTokenMetadata(String jti) {
        return fetch(ACCESS_PREFIX + jti);
    }

    public Optional<BlacklistedTokenMetadata> getRefreshTokenMetadata(String token) {
        return fetch(REFRESH_PREFIX + token);
    }

    private void store(String key, BlacklistedTokenMetadata metadata, long ttlSeconds) {
        try {
            template.opsForValue().set(key, metadata, Duration.ofSeconds(ttlSeconds));
        } catch (JacksonException e) {
            throw new TokenRevocationException("Failed to serialize token metadata for key: "+ key,e);
        }
    }
    private Optional<BlacklistedTokenMetadata> fetch(String key) {
        try {
        return Optional.ofNullable(template.opsForValue().get(key));
        } catch (JacksonException e) {
            throw new TokenRevocationException("Failed to deserialize token metadata for key: "+ key,e);

        }
    }

}
