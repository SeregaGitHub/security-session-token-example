package ru.kraser.session_security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.kraser.session_security.model.Role;
import ru.kraser.session_security.model.User;
import ru.kraser.session_security.service.UserService;

import java.util.List;

/*
  Сессия — серверное состояние.
 Горизонтальное масштабирование требует sticky sessions или Spring Session + Redis
 (иначе пользователь «вылетит» при балансировке между инстансами).
 Это плата за session-based.
 */

/*

                        Сессия по своей природе не предполагает reuse detection

Что можно сделать (аналоги reuse detection для SESSION)
Если хотите приблизиться к reuse detection в SESSION-версии:

1. Spring Session + SessionRegistry — ограничить количество сессий

http.sessionManagement(s -> s
    .maximumSessions(1)                    // только 1 активная сессия
    .maxSessionsPreventsLogin(true)        // при попытке второй — блокировать логин
    .expiredUrl("/login?expired")
);

Эффект: пользователь может быть залогинен только в одном месте.
        Если злоумышленник украл JSESSIONID и залогинился — старая сессия (жертвы) инвалидируется.
        Это похоже на reuse detection, но не детектит кражу — просто ограничивает количество.

Минус:  не работает в stateless (нужен SessionRegistry в памяти или Redis).

2. Привязка сессии к IP/User-Agent (session pinning)

// При создании сессии сохранить IP/UA, проверять на каждом запросе
session.setAttribute("ip", request.getRemoteAddr());
session.setAttribute("ua", request.getHeader("User-Agent"));

// В фильтре
if (!session.getAttribute("ip").equals(request.getRemoteAddr())) {
    session.invalidate();   // «сессия угнана» — инвалидировать
}

Эффект: если JSESSIONID украден и используется с другого IP/устройства — сессия инвалидируется.
        Это ближе к reuse detection (детектит «подозрительное» использование).

Минусы:

- ломается при смене IP (мобильный интернет, VPN);
- User-Agent можно подделать;
- не работает при легитимном использовании с нескольких устройств.
- Для production — спорная практика.

3. Логирование и мониторинг

// При каждом запросе логировать IP/UA + JSESSIONID
log.info("Request from IP={}, UA={}, session={}",
    request.getRemoteAddr(),
    request.getHeader("User-Agent"),
    request.getSession(false)?.getId());

Эффект: постфактум можно обнаружить аномалии (например, JSESSIONID используется с двух разных IP).
        Но автоматической реакции нет.
 */

/*
                        Что нужно сделать фронтенду:


Что должен делать фронтенд
 Полный чек-лист SPA
#	Действие	                            Детали
-----------------------------------------------------------------------------------------------------------------
1	Логин	                                POST /api/v1/auth с credentials: 'include'
2	После логина — получить CSRF-токен	    GET /api/v1/csrf с credentials: 'include' -> сохранить csrf_token в памяти
3	Каждый небезопасный запрос	            X-XSRF-TOKEN: <csrf_token> + credentials: 'include'
4	На 403 (токен невалиден)	            GET /api/v1/csrf -> обновить токен -> повторить запрос
5	На 401 (сессия истекла)	                Перелогиниться через /auth
6	Логаут	                                POST /api/v1/auth/logout с X-XSRF-TOKEN + credentials: 'include'
7	Не пытаться декодировать токен	        Отправлять csrf_token как есть — это XOR-маска, сервер сам её «снимет»
-----------------------------------------------------------------------------------------------------------------
* Ключевое для SPA: на всех fetch — credentials: 'include', иначе JSESSIONID не отправится.
* credentials: 'include' на всех запросах к бэкенду
* Хранить токен в памяти (JS-переменная)	localStorage уязвим к XSS
* Отправлять X-XSRF-TOKEN для всех POST/PUT/DELETE/PATCH
  Исключение: /auth (логин)
* НЕ отправлять CSRF для GET/HEAD/OPTIONS
-----------------------------------------------------------------------------------------------------------------
 */

@SpringBootApplication
public class Main implements CommandLineRunner {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }

    @Override
    public void run(String... args) throws Exception {

        List<String> users = List.of("admin", "technician", "employee");

        for (String username : users) {
            Role role = setRole(username);
            User user = User.builder()
                    .id(username)
                    .username(username)
                    .enabled(true)
                    .password(passwordEncoder.encode("1234"))
                    .role(role)
                    .build();
            userService.createDefaultUsers(user);
        }
    }

    private static Role setRole(String username) {
        Role role;
        switch (username) {
            case "admin" -> role = Role.ADMIN;
            case "technician" -> role = Role.TECHNICIAN;
            default -> role = Role.EMPLOYEE;
        }
        return role;
    }

}
