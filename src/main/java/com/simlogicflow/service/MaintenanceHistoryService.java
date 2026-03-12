package com.simlogicflow.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.MaintenanceHistoryDto;
import com.simlogicflow.model.Maintenance;
import com.simlogicflow.model.MaintenanceHistory;
import com.simlogicflow.repository.MaintenanceHistoryRepository;
import com.simlogicflow.repository.MaintenanceRepository;

import java.util.List;
import java.util.Optional;

@Service
public class MaintenanceHistoryService {

    @Autowired
    private MaintenanceHistoryRepository maintenanceHistoryRepository;

    @Autowired
    private MaintenanceRepository maintenanceRepository;

    public List<MaintenanceHistory> getAllMaintenanceHistories() {
        return maintenanceHistoryRepository.findAll();
    }

    public MaintenanceHistory createMaintenanceHistory(MaintenanceHistoryDto dto) {
        MaintenanceHistory history = new MaintenanceHistory();
        updateHistoryFromDto(history, dto);
        return maintenanceHistoryRepository.save(history);
    }

    public MaintenanceHistory updateMaintenanceHistory(Long id, MaintenanceHistoryDto dto) {
        Optional<MaintenanceHistory> optionalHistory = maintenanceHistoryRepository.findById(id);
        if (optionalHistory.isPresent()) {
            MaintenanceHistory history = optionalHistory.get();
            updateHistoryFromDto(history, dto);
            return maintenanceHistoryRepository.save(history);
        }
        throw new RuntimeException("MaintenanceHistory not found with id " + id);
    }

    public void deleteMaintenanceHistory(Long id) {
        maintenanceHistoryRepository.deleteById(id);
    }

    private void updateHistoryFromDto(MaintenanceHistory history, MaintenanceHistoryDto dto) {
        history.setObservation(dto.getObservation());
        history.setChangeDate(dto.getChangeDate());

        if (dto.getMaintenanceId() != null) {
            Maintenance maintenance = maintenanceRepository.findById(dto.getMaintenanceId())
                    .orElseThrow(() -> new RuntimeException("Maintenance not found with id " + dto.getMaintenanceId()));
            history.setMaintenance(maintenance);
        }
    }
}
