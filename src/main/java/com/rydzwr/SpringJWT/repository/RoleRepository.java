package com.rydzwr.SpringJWT.repository;

import com.rydzwr.SpringJWT.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}

