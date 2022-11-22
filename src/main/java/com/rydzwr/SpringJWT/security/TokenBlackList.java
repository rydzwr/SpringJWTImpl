package com.rydzwr.SpringJWT.security;

import java.util.HashSet;
import java.util.Set;

public class TokenBlackList {
    private static TokenBlackList instance;
    private static Set<String> list = new HashSet<>();

    public boolean contains(String token) {
        return list.contains(token);
    }

    public void add(String token) {
        list.add(token);
    }

    public static TokenBlackList getInstance() {
        if (instance == null) {
            instance = new TokenBlackList();
        }
        return instance;
    }
}
