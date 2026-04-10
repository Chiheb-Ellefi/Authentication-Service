package delivery.system.authorizationservice.models.others;



import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class BlacklistedTokenMetadata implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private RevocationReason reason;


    private String username;
    private Set<String> roles;


    private String jti;
    private String tokenType;


    private LocalDateTime revokedAt;
    private LocalDateTime tokenExpiresAt;


    private String revokedByIp;
    private String userAgent;
    private String revokedBy;
}