package com.rydzwr.SpringJWT.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rydzwr.SpringJWT.model.Role;
import com.rydzwr.SpringJWT.model.User;
import com.rydzwr.SpringJWT.model.UserDataResponse;
import com.rydzwr.SpringJWT.security.TokenBlackList;
import com.rydzwr.SpringJWT.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/data/user")
    public UserDataResponse home() {
        return new UserDataResponse("user public data");
    }

    @GetMapping("/data/admin")
    public UserDataResponse admin() {
        return new UserDataResponse("admin only data");
    }

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        Map<String, Cookie> cookieMap = new HashMap<>();
        for (Cookie cookie : cookies) {
            cookieMap.put(cookie.getName(), cookie);
        }

        if (!cookieMap.containsKey("jwt")) {
            response.setStatus(204);
            return;
        }

        Cookie deleteJWT = new Cookie("jwt", null);
        deleteJWT.setMaxAge(0);
        deleteJWT.setHttpOnly(true);
        response.addCookie(deleteJWT);

        String authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring("Bearer ".length());
            TokenBlackList.getInstance().add(token);
        }

        User user = userService.findByRefreshToken(cookieMap.get("jwt").getValue());

        if (user == null) {
            response.setStatus(204);
            return;
        }

        user.setRefreshToken(null);
        userService.saveUser(user);
        response.setStatus(204);
    }

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        Map<String, Cookie> cookieMap = new HashMap<>();
        for (Cookie cookie : cookies) {
            cookieMap.put(cookie.getName(), cookie);
        }

        if (!cookieMap.containsKey("jwt")) {
            sendError(response, "Token Is Missing");
        }

        try {
            String refreshToken = cookieMap.get("jwt").getValue();
            Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
            User user = userService.findByRefreshToken(refreshToken);

            if (user == null) {
                sendError(response, "Cannot find user");
                return;
            }

            String accessToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                    .withIssuer(request.getRequestURI())
                    .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                    .sign(algorithm);
            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken);

            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), tokens);

        } catch (Exception e) {
            response.setHeader("error", e.getMessage());
            response.setStatus(FORBIDDEN.value());

            Map<String, String> error = new HashMap<>();
            error.put("error_message", e.getMessage());

            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), error);
        }
    }

    private void sendError(HttpServletResponse response, String message) throws IOException {
        response.setHeader("error", message);
        response.setStatus(UNAUTHORIZED.value());

        Map<String, String> error = new HashMap<>();
        error.put("error_message", message);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
