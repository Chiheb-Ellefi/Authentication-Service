package delivery.system.authorizationservice.entities;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name="authorities")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Authority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String name;
}
