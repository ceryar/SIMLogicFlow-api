package com.simlogicflow.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.LoginDto;
import com.simlogicflow.model.User;
import com.simlogicflow.repository.UserRepository;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User login(LoginDto logintDto){

        User user = userRepository.findByEmail(logintDto.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if(!passwordEncoder.matches(logintDto.getPassword(), user.getPassword())){
            throw new RuntimeException("Contraseña incorrecta");
        }

        return user;
    }

}
