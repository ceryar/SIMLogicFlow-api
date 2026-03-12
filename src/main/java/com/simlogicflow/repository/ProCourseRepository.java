package com.simlogicflow.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.simlogicflow.model.ProCourse;

@Repository
public interface ProCourseRepository extends JpaRepository<ProCourse, Long> {

    @org.springframework.data.jpa.repository.Query("SELECT p FROM ProCourse p " +
            "WHERE p.course.simulator.id = :simulatorId " +
            "AND p.fecha = :fecha " +
            "AND p.horaini < :horafin AND p.horafin > :horaini " +
            "AND (:excludeId IS NULL OR p.id != :excludeId)")
    java.util.List<ProCourse> findOverlappingProCourses(
            @org.springframework.data.repository.query.Param("simulatorId") Long simulatorId,
            @org.springframework.data.repository.query.Param("fecha") java.time.LocalDate fecha,
            @org.springframework.data.repository.query.Param("horaini") java.time.LocalTime horaini,
            @org.springframework.data.repository.query.Param("horafin") java.time.LocalTime horafin,
            @org.springframework.data.repository.query.Param("excludeId") Long excludeId);
}
