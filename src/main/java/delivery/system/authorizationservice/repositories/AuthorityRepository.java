package delivery.system.authorizationservice.repositories;

import delivery.system.authorizationservice.entities.Authority;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority, Long> {
    Optional<Authority> findByName(String name);
    @Transactional
    void deleteByName(String name);
}
