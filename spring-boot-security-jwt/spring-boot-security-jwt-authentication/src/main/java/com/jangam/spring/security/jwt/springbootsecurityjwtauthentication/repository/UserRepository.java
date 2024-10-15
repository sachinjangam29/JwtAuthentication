package com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.repository;

import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import javax.swing.text.html.Option;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String message);

   Optional<User> findByUsername(String username);
}
