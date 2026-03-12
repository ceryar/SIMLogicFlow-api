package com.simlogicflow.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.simlogicflow.model.Role;
import com.simlogicflow.model.User;
import com.simlogicflow.repository.RolRepository;
import com.simlogicflow.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class DatabaseSeeder implements CommandLineRunner {

    private final RolRepository rolRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        seedRoles();
        seedAdminUser();
    }

    private void seedRoles() {
        List<String> roleNames = Arrays.asList(
                "ADMINISTRADOR",
                "ESTUDIANTE",
                "PSEUDOPILOTO",
                "INSTRUCTOR",
                "COORACAD");

        for (String roleName : roleNames) {
            if (rolRepository.findByName(roleName).isEmpty()) {
                rolRepository.save(Role.builder()
                        .name(roleName)
                        .description("Rol de " + roleName.toLowerCase())
                        .build());
                System.out.println("Rol creado: " + roleName);
            }
        }
    }

    private void seedAdminUser() {
        String adminEmail = "admin@email.com";
        if (userRepository.findByEmail(adminEmail).isEmpty()) {
            Role adminRole = rolRepository.findByName("ADMINISTRADOR")
                    .orElseThrow(() -> new RuntimeException("Error: Rol ADMINISTRADOR no encontrado."));

            User admin = User.builder()
                    .firstName("Admin")
                    .lastname("System")
                    .email(adminEmail)
                    .password(passwordEncoder.encode("admin123"))
                    .role(adminRole)
                    .documentNumber("0000000000")
                    .active(true)
                    .mustChangePassword(false)
                    .build();

            userRepository.save(admin);
            System.out.println("Usuario administrador creado: " + adminEmail);
        }
    }
}
