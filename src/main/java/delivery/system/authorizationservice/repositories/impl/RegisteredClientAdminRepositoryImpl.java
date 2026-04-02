package delivery.system.authorizationservice.repositories.impl;

import delivery.system.authorizationservice.repositories.RegisteredClientAdminRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class RegisteredClientAdminRepositoryImpl implements RegisteredClientAdminRepository {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public void deleteByClientId(String clientId) {
        String sql = "DELETE FROM oauth2_registered_client WHERE client_id = ?";
        jdbcTemplate.update(sql, clientId);
    }

    @Override
    public boolean existsByClientName(String clientName) {
        String sql = "SELECT EXISTS(SELECT 1 FROM oauth2_registered_client WHERE client_name = ?)";
        return Boolean.TRUE.equals(jdbcTemplate.queryForObject(sql, Boolean.class, clientName));
    }
}
