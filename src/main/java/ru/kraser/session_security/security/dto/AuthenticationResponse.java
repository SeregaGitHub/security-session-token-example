package ru.kraser.session_security.security.dto;

import lombok.Builder;
import ru.kraser.session_security.model.Role;

@Builder
public record AuthenticationResponse(
        String username,
        Role role
) {
}
