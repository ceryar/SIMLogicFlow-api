package com.simlogicflow.controller;

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

import com.simlogicflow.dto.MaintenanceTypeDto;
import com.simlogicflow.model.MaintenanceType;
import com.simlogicflow.service.MaintenanceTypeService;

@RestController
@RequestMapping("/api/v1/maintenance-types")
@PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'TECNICO')")
public class MaintenanceTypeController {

    @Autowired
    private MaintenanceTypeService maintenanceTypeService;

    @GetMapping
    public List<MaintenanceType> getAllMaintenanceTypes() {
        return maintenanceTypeService.getAllMaintenanceTypes();
    }

    @PostMapping
    public MaintenanceType createMaintenanceType(@RequestBody MaintenanceTypeDto dto) {
        return maintenanceTypeService.createMaintenanceType(dto);
    }

    @PutMapping("/{id}")
    public MaintenanceType updateMaintenanceType(@PathVariable Long id, @RequestBody MaintenanceTypeDto dto) {
        return maintenanceTypeService.updateMaintenanceType(id, dto);
    }

    @DeleteMapping("/{id}")
    public void deleteMaintenanceType(@PathVariable Long id) {
        maintenanceTypeService.deleteMaintenanceType(id);
    }

}
