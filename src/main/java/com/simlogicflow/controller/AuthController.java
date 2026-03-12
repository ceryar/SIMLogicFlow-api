package com.simlogicflow.controller;

import com.simlogicflow.SecurityConfig.JwtUtil;
import com.simlogicflow.dto.AuthResponse;
import com.simlogicflow.dto.LoginDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private com.simlogicflow.repository.UserRepository userRepository;

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword()));

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtUtil.generateToken(userDetails);

        String email = userDetails.getUsername();
        String role = userDetails.getAuthorities().stream().findFirst()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority).orElse("");

        com.simlogicflow.model.User user = userRepository.findByEmail(email).orElse(null);
        Long userId = user != null ? user.getId() : null;
        Boolean mustChangePassword = user != null ? user.getMustChangePassword() : false;

        return new AuthResponse(token, email, role, userId, mustChangePassword);
    }
}
