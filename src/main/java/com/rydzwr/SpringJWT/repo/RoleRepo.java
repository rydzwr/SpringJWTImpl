package com.rydzwr.SpringJWT.repo;

import com.rydzwr.SpringJWT.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}

