package delivery.system.authorizationservice.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenRevocationService {
    private final BlacklistService blacklistService;


}
