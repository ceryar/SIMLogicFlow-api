package com.simlogicflow.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.MaintenanceDto;
import com.simlogicflow.model.Maintenance;
import com.simlogicflow.model.MaintenanceType;
import com.simlogicflow.model.Simulator;
import com.simlogicflow.repository.MaintenanceRepository;
import com.simlogicflow.repository.MaintenanceTypeRepository;
import com.simlogicflow.repository.SimulatorRepository;

@Service
public class MaintenanceService {

    @Autowired
    private MaintenanceRepository maintenanceRepository;

    @Autowired
    private SimulatorRepository simulatorRepository;

    @Autowired
    private MaintenanceTypeRepository maintenanceTypeRepository;

    @Autowired
    private com.simlogicflow.repository.ProCourseRepository proCourseRepository;

    public List<Maintenance> getAllMaintenances() {
        return maintenanceRepository.findAll();
    }

    public Maintenance createMaintenance(MaintenanceDto dto) {
        Maintenance maintenance = new Maintenance();
        updateMaintenanceFromDto(maintenance, dto);
        return maintenanceRepository.save(maintenance);
    }

    public Maintenance updateMaintenance(Long id, MaintenanceDto dto) {
        Optional<Maintenance> optionalMaintenance = maintenanceRepository.findById(id);
        if (optionalMaintenance.isPresent()) {
            Maintenance maintenance = optionalMaintenance.get();
            updateMaintenanceFromDto(maintenance, dto);
            return maintenanceRepository.save(maintenance);
        }
        throw new RuntimeException("Maintenance not found with id " + id);
    }

    public void deleteMaintenance(Long id) {
        maintenanceRepository.deleteById(id);
    }

    private void updateMaintenanceFromDto(Maintenance maintenance, MaintenanceDto dto) {
        maintenance.setDescription(dto.getDescription());
        maintenance.setFecIni(dto.getFecIni());
        maintenance.setFecFin(dto.getFecFin());
        maintenance.setHoraIni(dto.getHoraIni());
        maintenance.setHoraFin(dto.getHoraFin());

        if (dto.getSimulatorId() != null) {
            Simulator simulator = simulatorRepository.findById(dto.getSimulatorId())
                    .orElseThrow(() -> new RuntimeException("Simulator not found with id " + dto.getSimulatorId()));
            maintenance.setSimulator(simulator);
        }

        if (dto.getMaintenanceTypeId() != null) {
            MaintenanceType maintenanceType = maintenanceTypeRepository.findById(dto.getMaintenanceTypeId())
                    .orElseThrow(() -> new RuntimeException(
                            "MaintenanceType not found with id " + dto.getMaintenanceTypeId()));
            maintenance.setMaintenanceType(maintenanceType);
        }

        validateNoOverlap(maintenance.getSimulator().getId(), dto.getFecIni(), dto.getFecFin(),
                dto.getHoraIni(), dto.getHoraFin(), maintenance.getId());
    }

    private void validateNoOverlap(Long simulatorId, java.time.LocalDate fecIni, java.time.LocalDate fecFin,
            java.time.LocalTime horaIni, java.time.LocalTime horaFin, Long excludeId) {
        // Check overlap with other maintenances (by date; refine with time for
        // same-day)
        List<Maintenance> overlaps = maintenanceRepository.findOverlappingMaintenances(simulatorId, fecIni, fecFin,
                excludeId);
        for (Maintenance other : overlaps) {
            // Same-day range: check time overlap
            boolean datesOverlap = !fecIni.isAfter(other.getFecFin()) && !fecFin.isBefore(other.getFecIni());
            if (!datesOverlap)
                continue;
            // If date ranges overlap beyond a single day, always conflict
            boolean singleDayConflict = fecIni.equals(fecFin) && other.getFecIni().equals(other.getFecFin())
                    && fecIni.equals(other.getFecIni());
            if (!singleDayConflict || (horaIni.isBefore(other.getHoraFin()) && horaFin.isAfter(other.getHoraIni()))) {
                throw new com.simlogicflow.exceptions.ScheduleConflictException(
                        "Ya existe un mantenimiento programado en este simulador que se cruza con el rango de fechas y horas especificado.");
            }
        }

        // Check overlap with scheduled ProCourses
        java.time.LocalDate currentD = fecIni;
        while (!currentD.isAfter(fecFin)) {
            java.time.LocalTime checkIni = currentD.equals(fecIni) ? horaIni : java.time.LocalTime.MIN;
            java.time.LocalTime checkFin = currentD.equals(fecFin) ? horaFin : java.time.LocalTime.MAX;
            List<com.simlogicflow.model.ProCourse> pcOverlaps = proCourseRepository.findOverlappingProCourses(
                    simulatorId, currentD, checkIni, checkFin, null);
            if (!pcOverlaps.isEmpty()) {
                throw new com.simlogicflow.exceptions.ScheduleConflictException(
                        "Ya existe un curso programado en la fecha " + currentD
                                + " con horario que se cruza con el mantenimiento.");
            }
            currentD = currentD.plusDays(1);
        }
    }
}
