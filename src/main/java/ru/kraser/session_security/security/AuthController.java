package ru.kraser.session_security.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import ru.kraser.session_security.security.dto.AuthenticationRequest;
import ru.kraser.session_security.security.dto.AuthenticationResponse;

import static ru.kraser.session_security.util.Utilities.*;

@RestController
@RequestMapping(value = BASE_URL)
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping(AUTH_URL)
    public ResponseEntity<AuthenticationResponse> authenticate(
            @Validated @RequestBody AuthenticationRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        log.info("Authenticating user '{}'...", request.username());
        AuthenticationResponse response =
                authenticationService.authenticate(request, httpRequest, httpResponse);
        log.info("User '{}' authenticated successfully", request.username());
        return ResponseEntity.ok(response);
    }

    @PostMapping(AUTH_URL + LOGOUT_URL)
    public ResponseEntity<Void> logout(HttpServletRequest httpRequest, HttpServletResponse response) {
        log.info("Attempting to logout...");
        authenticationService.logout(httpRequest);

        // Удаляем JSESSIONID cookie на клиенте (если нужно)
        ResponseCookie deleteSessionCookie = ResponseCookie.from("JSESSIONID", "")
                .httpOnly(true)
                .secure(false) // в prod: true
                .path("/")
                .sameSite("Strict")
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, deleteSessionCookie.toString());

        log.info("Logout successful");
        return ResponseEntity.noContent().build();
    }
}
