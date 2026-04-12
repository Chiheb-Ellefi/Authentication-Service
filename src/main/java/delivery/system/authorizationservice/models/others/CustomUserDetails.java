package delivery.system.authorizationservice.models.others;

import com.fasterxml.jackson.annotation.*;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.jackson.Jacksonized;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.Set;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Builder
@Jacksonized
public class CustomUserDetails implements UserDetails {

    @JsonProperty("id")
    private final Long id;

    @JsonProperty("username")
    private final String username;

    @JsonProperty("password")
    private final String password;

    @JsonProperty("enabled")
    private final boolean enabled;

    @JsonProperty("accountNonExpired")
    private final boolean accountNonExpired;

    @JsonProperty("accountNonLocked")
    private final boolean accountNonLocked;

    @JsonProperty("credentialsNonExpired")
    private final boolean credentialsNonExpired;

    @JsonProperty("authorities")
    private final Set<String> authorities;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities == null
                ? Set.of()
                : authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public @Nullable String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}