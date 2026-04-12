package delivery.system.authorizationservice.config;


import delivery.system.authorizationservice.models.others.BlacklistedTokenMetadata;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.*;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.util.Map;

@Configuration
@EnableCaching
public class RedisConfig {


    @Bean
    public RedisTemplate<String, BlacklistedTokenMetadata> redisTemplate(
            RedisConnectionFactory factory
    ) {
        RedisTemplate<String, BlacklistedTokenMetadata> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        template.setKeySerializer(new StringRedisSerializer());
        JacksonJsonRedisSerializer<BlacklistedTokenMetadata> serializer =
                new JacksonJsonRedisSerializer<>(BlacklistedTokenMetadata.class);
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);
        template.afterPropertiesSet();
        return template;
    }

    @Bean
    public RedisTemplate<String, OAuth2AuthenticatedPrincipal> redisPrincipalTemplate(
            RedisConnectionFactory factory
    ) {
        RedisTemplate<String, OAuth2AuthenticatedPrincipal> template = new RedisTemplate<>();
        JacksonJsonRedisSerializer<OAuth2AuthenticatedPrincipal> serializer =
                new JacksonJsonRedisSerializer<>(OAuth2AuthenticatedPrincipal.class);
        template.setConnectionFactory(factory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);
        template.afterPropertiesSet();
        return template;
    }


    @Bean
    public RedisCacheManager cacheManager(RedisConnectionFactory factory,ObjectMapper objectMapper) {


        RedisCacheConfiguration defaultConfig = RedisCacheConfiguration
                .defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(10))
                .serializeValuesWith(
                        RedisSerializationContext.SerializationPair
                                .fromSerializer(new GenericJacksonJsonRedisSerializer(objectMapper))
                )
                .disableCachingNullValues();


        Map<String, RedisCacheConfiguration> cacheConfigs = Map.of(
                "users",    defaultConfig.entryTtl(Duration.ofHours(1)),
                "sessions", defaultConfig.entryTtl(Duration.ofMinutes(30)),
                "products", defaultConfig.entryTtl(Duration.ofDays(1))
        );

        return RedisCacheManager.builder(factory)
                .cacheDefaults(defaultConfig)
                .withInitialCacheConfigurations(cacheConfigs)
                .build();
    }
}
