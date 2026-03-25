package delivery.system.authorizationservice.entities;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @Column(nullable = false, unique = true)
    private String username;
    @Column(nullable = false)
    private String password;
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @Builder.Default
    private boolean enabled=true;
    @Builder.Default
    private boolean accountNonExpired=true;
    @Builder.Default
    private boolean accountNonLocked=true;
    @Builder.Default
    private boolean credentialsNonExpired=true;


    private LocalDateTime lastLogin;
    private LocalDateTime passwordChangedAt;
    private LocalDateTime lockedAt;
    @Builder.Default
    private Integer failedLoginAttempts=0;

    public void lock() {
        this.accountNonLocked = false;
        this.lockedAt = LocalDateTime.now();
    }
    public void unlock() {
        this.setAccountNonLocked(true);
        this.setLockedAt(null);
        this.setFailedLoginAttempts(0);
    }
    public void enable(){
        this.enabled=true;
    }
    public void disable(){
        this.enabled=false;
    }
    public void expire(){
        this.accountNonExpired=false;
    }
    public void unexpire(){
        this.accountNonExpired=true;
    }
    public void loginFailed(){
        this.failedLoginAttempts++;
    }
    public void loginSucceed(){
        this.lastLogin=LocalDateTime.now();
    }

}
