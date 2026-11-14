package ru.kraser.session_security.security;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static ru.kraser.session_security.util.Utilities.BASE_URL;
import static ru.kraser.session_security.util.Utilities.CSRF_URL;

@RestController
@RequestMapping(BASE_URL)
public class CsrfController {

/*
                    Побочный эффект: анонимная сессия

GET /csrf без аутентификации создаёт HttpSession (для хранения токена). Это не бесплатно:

память на сервере (объект HttpSession для каждого анонимного клиента);
потенциальный DoS: злоумышленник дёргает /csrf миллион раз -> миллион сессий.

Митигация: server.servlet.session.timeout=30m ограничивает время жизни, но не количество.
В production с высоким трафиком стоит:

- поставить rate limiting на /csrf;
- или перейти на CookieCsrfTokenRepository (stateless, не создаёт сессию) — но тогда теряете Synchronizer Pattern.

Для учебного проекта — приемлемо. Для production — продумать.
*/

    @GetMapping(CSRF_URL)
    public ResponseEntity<Map<String, String>> csrf(CsrfToken token) {
        // Spring автоматически инжектит CsrfToken, если он материализован
        return ResponseEntity.ok(Map.of("csrf_token", token.getToken()));
    }
}
