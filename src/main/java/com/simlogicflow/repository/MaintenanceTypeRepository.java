package com.simlogicflow.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.simlogicflow.model.MaintenanceType;

@Repository
public interface MaintenanceTypeRepository extends JpaRepository<MaintenanceType, Long> {
}
