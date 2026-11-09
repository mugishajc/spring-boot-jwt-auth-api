package io.github.mugishajc.authapi.user;

import io.github.mugishajc.authapi.security.AccessTokenClaims;
import io.github.mugishajc.authapi.user.dto.UserResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Users")
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal AccessTokenClaims principal) {
        return userService.get(principal.userId());
    }
}
