package com.rydzwr.SpringJWT.repository;

import com.rydzwr.SpringJWT.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByRefreshToken(String token);
    @Query(value = "SELECT * FROM USERS WHERE username = ?1", nativeQuery = true)
    User findByUsername(String username);
}
