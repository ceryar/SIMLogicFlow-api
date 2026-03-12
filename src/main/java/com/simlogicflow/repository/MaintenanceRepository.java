package com.simlogicflow.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.simlogicflow.model.Maintenance;

@Repository
public interface MaintenanceRepository extends JpaRepository<Maintenance, Long> {

    @org.springframework.data.jpa.repository.Query("SELECT m FROM Maintenance m " +
            "WHERE m.simulator.id = :simulatorId " +
            "AND m.fecIni <= :fecFin AND m.fecFin >= :fecIni " +
            "AND (:excludeId IS NULL OR m.id != :excludeId)")
    java.util.List<Maintenance> findOverlappingMaintenances(
            @org.springframework.data.repository.query.Param("simulatorId") Long simulatorId,
            @org.springframework.data.repository.query.Param("fecIni") java.time.LocalDate fecIni,
            @org.springframework.data.repository.query.Param("fecFin") java.time.LocalDate fecFin,
            @org.springframework.data.repository.query.Param("excludeId") Long excludeId);
}
