package com.rydzwr.SpringJWT.service;

import com.rydzwr.SpringJWT.model.Role;
import com.rydzwr.SpringJWT.model.User;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String userName, String roleName);
    User findByUserName(String userName);
    User findByRefreshToken(String token);
}
