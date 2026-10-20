package com.ratelimiter.authservice.service;

import com.ratelimiter.authservice.dto.UserSummary;
import com.ratelimiter.authservice.exception.ApiException;
import com.ratelimiter.authservice.model.Role;
import com.ratelimiter.authservice.model.User;
import com.ratelimiter.authservice.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;

@Service
public class AdminUserService {

    private static final Logger log = LoggerFactory.getLogger(AdminUserService.class);

    private final UserRepository users;
    private final Clock clock;

    public AdminUserService(UserRepository users, Clock clock) {
        this.users = users;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<UserSummary> list(int page, int size) {
        return users.findAll(PageRequest.of(page, size, Sort.by("username"))).stream()
                .map(u -> toSummary(u))
                .toList();
    }

    @Transactional
    public UserSummary changeRole(String callerUsername, String rawTarget, String rawRole) {
        String target = AuthService.normalize(rawTarget);
        Role newRole = Role.parse(rawRole)
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, "role must be ADMIN, SELLER or CUSTOMER"));
        if (target.equals(AuthService.normalize(callerUsername))) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "You cannot change your own role");
        }
        User user = users.findByUsernameForUpdate(target)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "User not found"));
        if (user.getRole() == Role.ADMIN && newRole != Role.ADMIN && users.countByRole(Role.ADMIN) <= 1) {
            throw new ApiException(HttpStatus.CONFLICT, "Cannot remove the last administrator");
        }
        Role oldRole = user.getRole();
        user.setRole(newRole);
        log.info("AUDIT event=ROLE_CHANGED actor={} target={} from={} to={}",
                AuthService.normalize(callerUsername), target, oldRole, newRole);
        return toSummary(user);
    }

    private UserSummary toSummary(User user) {
        return new UserSummary(user.getUsername(), user.getRole().name(), user.isLocked(clock.instant()));
    }
}
