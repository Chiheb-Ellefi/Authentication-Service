package delivery.system.authorizationservice.security.filters;

import delivery.system.authorizationservice.exceptions.TokenRevokedException;
import delivery.system.authorizationservice.models.others.BlacklistedTokenMetadata;
import delivery.system.authorizationservice.services.BlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class TokenRevocationFilter extends OncePerRequestFilter {

    private final BlacklistService blacklistService;
    private final ObjectMapper objectMapper;
    private final JwtDecoder jwtDecoder;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.split(" ")[1];

        String jti=jwtDecoder.decode(token).getClaim("jti");
        if (blacklistService.isAccessRevoked(jti)) {
            BlacklistedTokenMetadata metadata = blacklistService
                    .getAccessTokenMetadata(jti)
                    .orElse(null);

            String reason = metadata != null
                    ? "Token revoked at: " + metadata.getRevokedAt() + ". Reason: " + metadata.getReason()
                    : "Token has been revoked.";

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write(objectMapper.writeValueAsString(
                    Map.of("error", "token_revoked", "message", reason)
            ));
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path= request.getRequestURI();
        return path.startsWith("/error") ||
                path.startsWith("/login") ||
                path.startsWith("/actuator/health") || path.startsWith("/api/v1/users/register");

    }


}