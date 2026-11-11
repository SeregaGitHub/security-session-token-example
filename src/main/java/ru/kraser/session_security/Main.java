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
В приложении - обычный Double-Submit, он уязвим к подмене cookie через subdomain или MITM
(если злоумышленник может установить свою cookie XSRF-TOKEN на домене приложения).
В этом случае он ставит своё значение в cookie, своё — в заголовок,
и проверка cookie == header проходит.

Signed Double-Submit решает эту проблему:
сервер подписывает токен (HMAC) перед установкой в cookie.
При проверке он валидирует подпись, а не просто сравнивает значения.
Злоумышленник не может подписать свой токен — у него нет секретного ключа.
 */

/*
  Сессия — серверное состояние.
 Горизонтальное масштабирование требует sticky sessions или Spring Session + Redis
 (иначе пользователь «вылетит» при балансировке между инстансами).
 Это плата за session-based.
 */

/*
                        Что нужно сделать фронтенду:


     Действие	        Было (JWT)	                             Стало (SESSION)
-----------------------------------------------------------------------------------------------------------------

* Логин	             POST /auth ->  	                POST /auth с credentials: 'include' ->
                     сохранить accessToken в памяти,    cookie JSESSIONID автоматически сохраняется браузером.
                     refreshToken в cookie              Перечитать X-XSRF-TOKEN после ответа (он ротирован)

* Обычные запросы	 Authorization:                     credentials: 'include' (cookie автоматически)
                     Bearer <access>

* Обновление 	     POST /refresh с X-XSRF-TOKEN	    Нет — сессия продлевается сама (sliding expiration),
  токена                                                Spring обновляет JSESSIONID

* CSRF	             X-XSRF-TOKEN     	                X-XSRF-TOKEN для всех POST/PUT/DELETE/PATCH (кроме /auth)
                     для /refresh и /logout

* Логаут	         POST /logout с X-XSRF-TOKEN	    POST /api/v1/auth/logout
                                                        с X-XSRF-TOKEN + credentials: 'include'

* 401 	             Повторить /refresh	                Перелогиниться (/auth заново)
( сессия
  истекла )
-----------------------------------------------------------------------------------------------------------------
* Ключевое для SPA: на всех fetch — credentials: 'include', иначе JSESSIONID не отправится.
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
