package io.github.mugishajc.authapi.user;

import io.github.mugishajc.authapi.security.AccessTokenClaims;
import io.github.mugishajc.authapi.user.dto.ChangeRoleRequest;
import io.github.mugishajc.authapi.user.dto.ChangeStatusRequest;
import io.github.mugishajc.authapi.user.dto.UserResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * User management for administrators. The URL is already restricted in
 * SecurityConfig; the annotation keeps the rule next to the code as well.
 */
@RestController
@Tag(name = "Admin")
@RequestMapping("/api/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public class AdminUserController {

    private final UserService userService;

    public AdminUserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public Page<UserResponse> list(@PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC)
                                   Pageable pageable) {
        return userService.list(pageable);
    }

    @GetMapping("/{id}")
    public UserResponse get(@PathVariable Long id) {
        return userService.get(id);
    }

    @PatchMapping("/{id}/role")
    public UserResponse changeRole(@AuthenticationPrincipal AccessTokenClaims principal,
                                   @PathVariable Long id, @Valid @RequestBody ChangeRoleRequest request) {
        return userService.changeRole(principal.userId(), id, request.role());
    }

    @PatchMapping("/{id}/status")
    public UserResponse changeStatus(@AuthenticationPrincipal AccessTokenClaims principal,
                                     @PathVariable Long id, @Valid @RequestBody ChangeStatusRequest request) {
        return userService.changeStatus(principal.userId(), id, request.enabled());
    }
}
