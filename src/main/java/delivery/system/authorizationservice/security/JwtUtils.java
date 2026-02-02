package delivery.system.authorizationservice.security;

import delivery.system.authorizationservice.models.CustomUserDetails;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {


    public String generateToken(CustomUserDetails user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("username", user.getUsername())
                .claim("authorities", user.getAuthorities())
                .claim("roles", user.getAuthorities())

                .compact();
    }

}
