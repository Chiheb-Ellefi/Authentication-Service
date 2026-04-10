package delivery.system.authorizationservice.config;


import delivery.system.authorizationservice.models.others.BlacklistedTokenMetadata;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import tools.jackson.databind.ObjectMapper;

@Configuration
public class RedisConfig {


    @Bean
    public RedisTemplate<String, BlacklistedTokenMetadata> redisTemplate(
            RedisConnectionFactory factory,
            ObjectMapper objectMapper
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
}