package ru.kraser.session_security.util;

import lombok.experimental.UtilityClass;

@UtilityClass
public class Utilities {

    public static final String BASE_URL = "/api/v1";
    public static final String AUTH_URL = "/auth";
    public static final String LOGOUT_URL = "/logout";
    public static final String CSRF_URL = "/csrf";
    public static final String OPEN_URL = "/open";
    public static final String DEFAULT_URL = "/default";

    public static final String ADMIN_URL = "/admin";
    public static final String TECHNICIAN_URL = "/technician";
    public static final String EMPLOYEE_URL = "/employee";

    // CSRF
    public static final String CSRF_COOKIE = "XSRF-TOKEN";
    public static final String CSRF_HEADER = "X-XSRF-TOKEN";
}
