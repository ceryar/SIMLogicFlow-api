package com.simlogicflow.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.simlogicflow.model.Role;

public interface RolRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
}
