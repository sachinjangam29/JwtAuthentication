package com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.repository;

import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.model.ERole;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
   Optional<Role> findByName(ERole name);
}
