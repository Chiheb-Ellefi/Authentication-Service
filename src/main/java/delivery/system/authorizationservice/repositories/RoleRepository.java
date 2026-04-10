package delivery.system.authorizationservice.repositories;

import delivery.system.authorizationservice.entities.Role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
    @Transactional
    void deleteByName(String name);


    @Query("SELECT DISTINCT r FROM Role r LEFT JOIN FETCH r.authorities")
    List<Role> findAllWithAuthorities();
}
