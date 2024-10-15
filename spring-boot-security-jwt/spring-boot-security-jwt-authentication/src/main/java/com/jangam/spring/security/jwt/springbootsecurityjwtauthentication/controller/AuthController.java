package com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.controller;

import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.model.ERole;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.model.Role;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.model.User;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.payload.request.LoginRequest;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.payload.request.SignupRequest;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.payload.response.JwtResponse;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.payload.response.MessageResponse;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.repository.RoleRepository;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.repository.UserRepository;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.security.jwt.JwtUtils;
import com.jangam.spring.security.jwt.springbootsecurityjwtauthentication.security.services.UserDetailsImpl;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final static Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> autheticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        logger.info("in authenticateUse method");

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        logger.info("processed till here ");
        String jwt = jwtUtils.generateToken(authentication);

        logger.info("jwt token " + jwt);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .toList();

        logger.info("Email"+ userDetails.getEmail());
        logger.info("Username"+ userDetails.getUsername());
        logger.info("Password"+ userDetails.getPassword());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already taken!"));
        }

        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                //  signupRequest.getPassword());
                passwordEncoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();
        logger.info("Roles defined is " + signupRequest.getRole());
        logger.info("Username is" + signupRequest.getUsername());
        logger.info("Password is " + signupRequest.getPassword());
        logger.info("Email is " + signupRequest.getEmail());
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            logger.info("Roles defined is -- UserRole---- " + strRoles);
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        logger.info("Roles defined is -- AdminRole---- " + strRoles);

                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        logger.info("Roles defined is -- ModRole---- " + strRoles);

                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        logger.info("Roles defined is -- UserRole Default---- " + strRoles);

                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
