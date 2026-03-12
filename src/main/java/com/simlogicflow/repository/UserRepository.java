package com.simlogicflow.repository;

import com.simlogicflow.model.Role;
import com.simlogicflow.model.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByRole(Role role);

}
