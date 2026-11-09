package io.github.mugishajc.authapi.user;

import io.github.mugishajc.authapi.auth.RefreshTokenService;
import io.github.mugishajc.authapi.common.NotFoundException;
import io.github.mugishajc.authapi.user.dto.UserResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
public class UserService {

    private final UserRepository users;
    private final RefreshTokenService refreshTokens;

    public UserService(UserRepository users, RefreshTokenService refreshTokens) {
        this.users = users;
        this.refreshTokens = refreshTokens;
    }

    @Transactional(readOnly = true)
    public UserResponse get(Long id) {
        return UserResponse.from(find(id));
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> list(Pageable pageable) {
        return users.findAll(pageable).map(UserResponse::from);
    }

    /**
     * Changing a role signs the user out everywhere, so the next access token
     * they obtain carries the new role. Admins cannot change their own role,
     * which avoids locking the last admin out by accident.
     */
    @Transactional
    public UserResponse changeRole(Long actingUserId, Long targetId, Role role) {
        rejectSelf(actingUserId, targetId, "You cannot change your own role");
        User user = find(targetId);
        if (user.getRole() != role) {
            user.setRole(role);
            refreshTokens.revokeAll(user);
        }
        return UserResponse.from(user);
    }

    @Transactional
    public UserResponse changeStatus(Long actingUserId, Long targetId, boolean enabled) {
        rejectSelf(actingUserId, targetId, "You cannot disable your own account");
        User user = find(targetId);
        user.setEnabled(enabled);
        if (!enabled) {
            refreshTokens.revokeAll(user);
        }
        return UserResponse.from(user);
    }

    private User find(Long id) {
        return users.findById(id).orElseThrow(() -> new NotFoundException("User " + id + " not found"));
    }

    private static void rejectSelf(Long actingUserId, Long targetId, String message) {
        if (Objects.equals(actingUserId, targetId)) {
            throw new IllegalStateException(message);
        }
    }
}
