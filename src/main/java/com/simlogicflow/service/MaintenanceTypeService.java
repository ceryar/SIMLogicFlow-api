package com.simlogicflow.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.MaintenanceTypeDto;
import com.simlogicflow.model.MaintenanceType;
import com.simlogicflow.repository.MaintenanceTypeRepository;

import java.util.List;
import java.util.Optional;

@Service
public class MaintenanceTypeService {

    @Autowired
    private MaintenanceTypeRepository maintenanceTypeRepository;

    public List<MaintenanceType> getAllMaintenanceTypes() {
        return maintenanceTypeRepository.findAll();
    }

    public MaintenanceType createMaintenanceType(MaintenanceTypeDto dto) {
        MaintenanceType maintenanceType = new MaintenanceType();
        updateMaintenanceTypeFromDto(maintenanceType, dto);
        return maintenanceTypeRepository.save(maintenanceType);
    }

    public MaintenanceType updateMaintenanceType(Long id, MaintenanceTypeDto dto) {
        Optional<MaintenanceType> optionalMaintenanceType = maintenanceTypeRepository.findById(id);
        if (optionalMaintenanceType.isPresent()) {
            MaintenanceType maintenanceType = optionalMaintenanceType.get();
            updateMaintenanceTypeFromDto(maintenanceType, dto);
            return maintenanceTypeRepository.save(maintenanceType);
        }
        throw new RuntimeException("MaintenanceType not found with id " + id);
    }

    public void deleteMaintenanceType(Long id) {
        maintenanceTypeRepository.deleteById(id);
    }

    private void updateMaintenanceTypeFromDto(MaintenanceType maintenanceType, MaintenanceTypeDto dto) {
        maintenanceType.setName(dto.getName());
        maintenanceType.setDescription(dto.getDescription());
    }
}
