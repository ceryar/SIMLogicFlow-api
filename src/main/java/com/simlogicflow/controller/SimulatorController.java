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

import com.simlogicflow.dto.SimulatorDto;
import com.simlogicflow.model.Simulator;
import com.simlogicflow.service.SimulatorService;

@RestController
@RequestMapping("/api/v1/simulators")
public class SimulatorController {

    @Autowired
    private SimulatorService simulatorService;

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD', 'TECNICO')")
    public List<Simulator> getAllSimulators() {
        return simulatorService.getAllSimulators();
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public Simulator createSimulator(@RequestBody SimulatorDto dto) {
        return simulatorService.createSimulator(dto);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public Simulator updateSimulator(@PathVariable("id") Long id, @RequestBody SimulatorDto dto) {
        return simulatorService.updateSimulator(id, dto);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public void deleteSimulator(@PathVariable("id") Long id) {
        simulatorService.deleteSimulator(id);
    }

}
