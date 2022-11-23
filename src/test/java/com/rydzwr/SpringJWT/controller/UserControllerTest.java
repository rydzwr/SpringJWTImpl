package com.rydzwr.SpringJWT.controller;

import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.json.JSONParser;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.Cookie;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class UserControllerTest {
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext context;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    public void e2eApiTest() throws Exception {
        final String[] results = new String[2];
        this.mockMvc.perform(
                        post("/api/login")
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                .param("username", "Admin")
                                .param("password", "1234")
        ).andDo(new ResultHandler() {
            @Override
            public void handle(MvcResult result) throws Exception {
                var parser = new JSONObject(result.getResponse().getContentAsString());
                results[0] = parser.getString("access_token");
                results[1] = parser.getString("role");
            }
        });
        log.info("Access TOKEN --> " + results[0]);
        log.info("ROLE --> " + results[1]);

        String accessToken = results[0];
        String userRole = results[1];

        assertNotNull(accessToken);
        assertThat(userRole, equalTo("ROLE_ADMIN"));

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);

        String expected = """
                {"data":"admin only data"}
                """;

        this.mockMvc.perform(
                        get("/api/data/admin")
                                .contentType(APPLICATION_JSON)
                                .headers(headers)
                )
                .andDo(print()).andExpect(content().string(expected.trim()));

        this.mockMvc.perform(
                        get("/api/data/user")
                                .headers(headers))
                .andExpect(status().isForbidden());
    }

    @Test
    public void shouldReturnNewAccessToken() throws Exception {
        final String[] results = new String[1];
        List<Cookie> cookies = new ArrayList<>();
        this.mockMvc.perform(
                post("/api/login")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("username", "Admin")
                        .param("password", "1234")
        ).andDo(new ResultHandler() {
            @Override
            public void handle(MvcResult result) throws Exception {
                var parser = new JSONObject(result.getResponse().getContentAsString());
                cookies.addAll(Arrays.stream(result.getResponse().getCookies()).toList());
                results[0] = parser.getString("access_token");
            }
        });
        log.info("Access TOKEN --> " + results[0]);

        String accessToken = results[0];

        Cookie refreshTokenCookie = cookies.stream().filter((cookie) -> cookie.getName().equals("jwt")).findAny().get();
        String refreshTokenValue = refreshTokenCookie.getValue();
        log.info("FOUND REFRESH TOKEN -->> " + refreshTokenValue);

        assertNotNull(accessToken);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);

        final String[] refreshResults = new String[1];

        this.mockMvc.perform(
                get("/api/token/refresh")
                        .headers(headers)
                        .cookie(new Cookie("jwt", refreshTokenValue))
        ).andDo(new ResultHandler() {
            @Override
            public void handle(MvcResult result) throws Exception {
                log.info("RESULT -->>" + result.getResponse().getContentAsString());
                var parser = new JSONObject(result.getResponse().getContentAsString());
                refreshResults[0] = parser.getString("access_token");
            }
        });

        String newAccessToken = refreshResults[0];
        assertNotEquals(accessToken, newAccessToken);
    }

    @Test
    public void shouldReturnIsForbiddenForAdmin() throws Exception {
        this.mockMvc.perform(
                        get("/api/data/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void shouldReturnIsForbiddenForUser() throws Exception {
        this.mockMvc.perform(
                        get("/api/data/user"))
                .andExpect(status().isForbidden());
    }
}
