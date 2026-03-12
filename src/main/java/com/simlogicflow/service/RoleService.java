package com.simlogicflow.service;

import com.simlogicflow.dto.RoleDto;
import com.simlogicflow.model.Role;
import com.simlogicflow.repository.RolRepository;
import com.simlogicflow.repository.UserRepository;
import jakarta.transaction.Transactional;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class RoleService {

    @Autowired
    private RolRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    public Role createRole(RoleDto dto) {
        Role role = new Role();
        updateRoleFromDto(role, dto);
        return roleRepository.save(role);
    }

    public Role updateRole(Long id, RoleDto dto) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Rol no encontrado con id " + id));

        // Verifica si el nuevo nombre ya está en uso por OTRO rol
        Optional<Role> existingRole = roleRepository.findAll().stream()
                .filter(r -> r.getName().equalsIgnoreCase(dto.getName()) && !r.getId().equals(id))
                .findFirst();

        if (existingRole.isPresent()) {
            throw new RuntimeException("El nombre del rol ya está en uso por otro registro.");
        }

        updateRoleFromDto(role, dto);
        return roleRepository.save(role);
    }

    public void deleteRole(Long id) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("El rol no existe o ya ha sido eliminado."));

        if (userRepository.existsByRole(role)) {
            throw new RuntimeException(
                    "No se puede eliminar el rol '" + role.getName() + "' porque está asignado a uno o más usuarios.");
        }

        roleRepository.delete(role);
    }

    private void updateRoleFromDto(Role role, RoleDto dto) {
        if (dto.getName() != null) {
            role.setName(dto.getName().toUpperCase());
        }
        role.setDescription(dto.getDescription());
    }
}
