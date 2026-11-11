package ru.kraser.session_security.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import ru.kraser.session_security.exception.AuthException;
import ru.kraser.session_security.model.User;
import ru.kraser.session_security.security.dto.AuthenticationRequest;
import ru.kraser.session_security.security.dto.AuthenticationResponse;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

/*
        Важно:

-    securityContextRepository.saveContext(...) — обязательно в SS6,
   иначе SecurityContextHolderFilter не восстановит контекст на следующем запросе.

-    session.invalidate() — контейнер сам выставит Set-Cookie: JSESSIONID=; Max-Age=0.

-    CsrfAuthenticationStrategy (Spring) сработает автоматически через AuthenticationSuccessEvent
   после authenticationManager.authenticate(...) → ротирует CSRF-токен (защита от session fixation).
*/

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    public AuthenticationResponse authenticate(AuthenticationRequest request,
                                               HttpServletRequest httpRequest,
                                               HttpServletResponse httpResponse) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.username(),
                            request.password()
                    )
            );
        } catch (AuthenticationException e) {
            throw new AuthException("Неверное имя пользователя или пароль !!!");
        }

        // Сохраняем контекст в HttpSession
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, httpRequest, httpResponse);
        // ^ создаёт HttpSession, кладёт SPRING_SECURITY_CONTEXT, ставит Set-Cookie: JSESSIONID

        User user = ((JwtUserDetails) authentication.getPrincipal()).getUser();

        return AuthenticationResponse.builder()
                .username(user.getUsername())
                .role(user.getRole())
                .build();
    }

    public void logout(HttpServletRequest httpRequest) {
        SecurityContextHolder.clearContext();
        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            session.invalidate();   // контейнер удалит JSESSIONID cookie
        }
    }
}