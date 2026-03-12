package com.simlogicflow.controller;

import com.simlogicflow.dto.MaintenanceHistoryDto;
import com.simlogicflow.model.MaintenanceHistory;
import com.simlogicflow.service.MaintenanceHistoryService;
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
@RequestMapping("/api/v1/maintenance-history")
@PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'TECNICO')")
public class MaintenanceHistoryController {

    @Autowired
    private MaintenanceHistoryService maintenanceHistoryService;

    @GetMapping
    public List<MaintenanceHistory> getAllMaintenanceHistories() {
        return maintenanceHistoryService.getAllMaintenanceHistories();
    }

    @PostMapping
    public MaintenanceHistory createMaintenanceHistory(@RequestBody MaintenanceHistoryDto dto) {
        return maintenanceHistoryService.createMaintenanceHistory(dto);
    }

    @PutMapping("/{id}")
    public MaintenanceHistory updateMaintenanceHistory(@PathVariable("id") Long id,
            @RequestBody MaintenanceHistoryDto dto) {
        return maintenanceHistoryService.updateMaintenanceHistory(id, dto);
    }

    @DeleteMapping("/{id}")
    public void deleteMaintenanceHistory(@PathVariable("id") Long id) {
        maintenanceHistoryService.deleteMaintenanceHistory(id);
    }

}
