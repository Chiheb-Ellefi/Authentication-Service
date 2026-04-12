package delivery.system.authorizationservice.security.filters;

import delivery.system.authorizationservice.models.others.BlacklistedTokenMetadata;
import delivery.system.authorizationservice.services.BlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
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
    private final OAuth2AuthorizationService authorizationService;

    @Value("${token.format}")
    private String TOKEN_FORMAT;

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

        String jti = resolveJti(token);

        if (jti == null) {
            filterChain.doFilter(request, response);
            return;
        }

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

    private String resolveJti(String token) {
        if ("reference".equalsIgnoreCase(TOKEN_FORMAT)) {

            OAuth2Authorization authorization = authorizationService.findByToken(
                    token, OAuth2TokenType.ACCESS_TOKEN);

            if (authorization == null) return null;

            OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                    authorization.getAccessToken();

            if (accessToken == null) return null;


            return (String) accessToken.getClaims().get(JwtClaimNames.JTI);

        } else {
            // Self-contained JWT
            try {
                return jwtDecoder.decode(token).getClaim(JwtClaimNames.JTI);
            } catch (Exception e) {
                return null;
            }
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.startsWith("/error") ||
                path.startsWith("/login") ||
                path.startsWith("/actuator/health") ||
                path.startsWith("/api/v1/users/register");
    }
}