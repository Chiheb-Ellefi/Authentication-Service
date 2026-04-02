package delivery.system.authorizationservice.repositories;




public interface RegisteredClientAdminRepository {
    void deleteByClientId(String clientId);
    boolean existsByClientName(String clientName);
}
