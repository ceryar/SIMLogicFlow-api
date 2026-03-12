package com.simlogicflow.controller;

import com.simlogicflow.dto.MaintenanceDto;
import com.simlogicflow.model.Maintenance;
import com.simlogicflow.service.MaintenanceService;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/maintenances")
@PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'TECNICO', 'ESTUDIANTE', 'INSTRUCTOR', 'PSEUDOPILOTO')")
public class MaintenanceController {

    @Autowired
    private MaintenanceService maintenanceService;

    @GetMapping
    public List<Maintenance> getAllMaintenances() {
        return maintenanceService.getAllMaintenances();
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'TECNICO')")
    public Maintenance createMaintenance(@RequestBody MaintenanceDto dto) {
        return maintenanceService.createMaintenance(dto);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'TECNICO')")
    public Maintenance updateMaintenance(@PathVariable("id") Long id, @RequestBody MaintenanceDto dto) {
        return maintenanceService.updateMaintenance(id, dto);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'TECNICO')")
    public void deleteMaintenance(@PathVariable("id") Long id) {
        maintenanceService.deleteMaintenance(id);
    }

}
