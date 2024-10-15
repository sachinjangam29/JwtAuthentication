package com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.security.services;

import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.model.User;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.repository.UserRepository;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow( () -> new UsernameNotFoundException("User not found with the username: "+ username));
        return UserDetailsImpl.build(user);
    }
}
