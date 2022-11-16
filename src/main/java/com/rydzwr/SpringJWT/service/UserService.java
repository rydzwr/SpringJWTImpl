package com.rydzwr.SpringJWT.service;

import com.rydzwr.SpringJWT.domain.Role;
import com.rydzwr.SpringJWT.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String userName, String roleName);
    User getUser(String userName);
    List<User> getUsers();
    void deleteAll();
}
