package ru.kraser.session_security.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import ru.kraser.session_security.model.Role;

import java.util.Collections;
import java.util.List;

import static ru.kraser.session_security.util.Utilities.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityWebConfiguration {

    // Нужно если в SecurityAppConfiguration есть бин AuthenticationProvider
    //private final AuthenticationProvider authenticationProvider;

    private final SecurityContextRepository securityContextRepository;

    @Value("${allowed.frontend.url}")
    private String allowedFrontendUrl;



    //if Synchronizer Token Pattern remove (only Double-Submit)

    //  only if no nginx (and if cross-origin: frontend and backend on differed ports)  //

/*    @Value("${app.cookie.csrf-same-site:Strict}")
    private String csrfCookieSameSite;

    @Value("${app.cookie.csrf-secure:false}")
    private boolean csrfCookieSecure;*/
    //  only if no nginx (and if cross-origin: frontend and backend on differed ports)  //

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(c -> c.configurationSource(corsConfigurationSource()))
                // прописываем все url которым нужен CSRF токен
                // login CSRF: OWASP рекомендует защищать все POST-эндпоинты, включая логин - тут отключена
                /*
                    нужно, чтобы жертва залогинилась под аккаунтом атакующего,
                    что требует от жертвы ввода пароля атакующего — маловероятно
                 */

                // CSRF — для ВСЕХ небезопасных методов, кроме /auth (логин)
                // login CSRF отключён: требует bootstrap GET перед логином, для демо — избыточно.
                // Почему ignoringRequestMatchers(/auth): логин не защищён CSRF,
                // потому что до логина у клиента может не быть CSRF-токена (нет сессии).
                // В prod можно убрать это исключение и добавить GET /api/v1/csrf (bootstrap-эндпоинт)
                // — SPA сначала получает токен, потом логинится.
                .csrf(csrf -> csrf
                     // .csrfTokenRepository(csrfRepository()) if Synchronizer Token Pattern remove (only Double-Submit)
                    // для prod можно рассмотреть XorCsrfTokenRequestAttributeHandler() // - защита от BREACH-атак
                        //.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()) // простой вариант
                        .csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers(BASE_URL + AUTH_URL)
                )
                .authorizeHttpRequests((request) -> request
                        .requestMatchers(BASE_URL + AUTH_URL)
                        .permitAll()
                        .requestMatchers(BASE_URL + AUTH_URL + LOGOUT_URL)
                        .permitAll()
                        .requestMatchers(BASE_URL + CSRF_URL)
                        .permitAll()
                        .requestMatchers(BASE_URL + OPEN_URL)
                        .permitAll()
                        .requestMatchers(BASE_URL + ADMIN_URL + "/**")
                        .hasRole(Role.ADMIN.name())
                        .requestMatchers(BASE_URL + TECHNICIAN_URL + "/**")
                        .hasAnyRole(Role.ADMIN.name(), Role.TECHNICIAN.name())
                        .requestMatchers(BASE_URL + EMPLOYEE_URL + "/**")
                        .hasAnyRole(Role.ADMIN.name(), Role.TECHNICIAN.name(), Role.EMPLOYEE.name())
                        .anyRequest().authenticated())
                // Сессия: IF_REQUIRED + защита от session fixation (смена ID при логине)
                .sessionManagement(
                        manager -> manager
                            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                            .sessionFixation(fixation -> fixation.changeSessionId())
                )
                // Нужно если в SecurityAppConfiguration есть бин AuthenticationProvider
                //.authenticationProvider(authenticationProvider)


                // Явно подключаем SecurityContextRepository, чтобы фильтр и AuthenticationService
                // использовали ОДИН и тот же репозиторий (HttpSession)
                .securityContext(sc -> sc.securityContextRepository(securityContextRepository))

                // Стандартный LogoutFilter отключаем — logout реализован в AuthController
                .logout(AbstractHttpConfigurer::disable);

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource() {
        return request -> {
            CorsConfiguration cfg = new CorsConfiguration();
            cfg.setAllowedOrigins(List.of(allowedFrontendUrl));
            cfg.setAllowedMethods(Collections.singletonList("*"));
            cfg.setAllowedHeaders(Collections.singletonList("*"));
            cfg.setExposedHeaders(List.of(CSRF_HEADER));   // SPA читает X-XSRF-TOKEN из ответа
            cfg.setAllowCredentials(true);                 // обязательно для session cookie
            cfg.setMaxAge(3600L);
            return cfg;
        };
    }

    /*

    if Synchronizer Token Pattern remove (only Double-Submit)

    private CookieCsrfTokenRepository csrfRepository() {
        CookieCsrfTokenRepository csrfTokenRepository =
                CookieCsrfTokenRepository.withHttpOnlyFalse(); // JS читает CsrfToken
        csrfTokenRepository.setCookieName(CSRF_COOKIE);
        csrfTokenRepository.setHeaderName(CSRF_HEADER);

        // only if no nginx (and if cross-origin: frontend and backend on differed ports) //
        csrfTokenRepository.setCookieCustomizer(cookie -> cookie
                .sameSite(csrfCookieSameSite)
                .secure(csrfCookieSecure));
        // only if no nginx (and if cross-origin: frontend and backend on differed ports) //

        return csrfTokenRepository;
    }*/
}
