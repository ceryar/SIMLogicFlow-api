package com.simlogicflow.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.ProCourseDto;
import com.simlogicflow.model.Course;
import com.simlogicflow.model.ProCourse;
import com.simlogicflow.repository.CourseRepository;
import com.simlogicflow.repository.ProCourseRepository;

@Service
public class ProCourseService {

    @Autowired
    private ProCourseRepository proCourseRepository;

    @Autowired
    private CourseRepository courseRepository;

    @Autowired
    private com.simlogicflow.repository.MaintenanceRepository maintenanceRepository;

    public List<ProCourse> getAllProCourses() {
        return proCourseRepository.findAll();
    }

    public ProCourse createProCourse(ProCourseDto dto) {
        ProCourse proCourse = new ProCourse();
        updateProCourseFromDto(proCourse, dto);
        return proCourseRepository.save(proCourse);
    }

    public ProCourse updateProCourse(Long id, ProCourseDto dto) {
        Optional<ProCourse> optionalProCourse = proCourseRepository.findById(id);
        if (optionalProCourse.isPresent()) {
            ProCourse proCourse = optionalProCourse.get();
            updateProCourseFromDto(proCourse, dto);
            return proCourseRepository.save(proCourse);
        }
        throw new RuntimeException("ProCourse not found with id " + id);
    }

    public void deleteProCourse(Long id) {
        proCourseRepository.deleteById(id);
    }

    private void updateProCourseFromDto(ProCourse proCourse, ProCourseDto dto) {
        proCourse.setHoraini(dto.getHoraini());
        proCourse.setHorafin(dto.getHorafin());
        proCourse.setHoras(dto.getHoras());
        proCourse.setFecha(dto.getFecha());

        if (dto.getCourseId() != null) {
            Course course = courseRepository.findById(dto.getCourseId())
                    .orElseThrow(() -> new RuntimeException("Course not found with id " + dto.getCourseId()));
            proCourse.setCourse(course);
        }

        validateNoOverlap(proCourse.getCourse().getSimulator().getId(), dto.getFecha(), dto.getHoraini(),
                dto.getHorafin(), proCourse.getId());
    }

    private void validateNoOverlap(Long simulatorId, java.time.LocalDate fecha, java.time.LocalTime horaini,
            java.time.LocalTime horafin, Long excludeId) {
        List<ProCourse> overlaps = proCourseRepository.findOverlappingProCourses(simulatorId, fecha, horaini, horafin,
                excludeId);
        if (!overlaps.isEmpty()) {
            throw new com.simlogicflow.exceptions.ScheduleConflictException(
                    "Ya existe un curso programado en este simulador para el horario especificado.");
        }

        List<com.simlogicflow.model.Maintenance> maintenanceOverlaps = maintenanceRepository
                .findOverlappingMaintenances(simulatorId, fecha, fecha, null);
        if (!maintenanceOverlaps.isEmpty()) {
            throw new com.simlogicflow.exceptions.ScheduleConflictException(
                    "El simulador se encuentra en mantenimiento en la fecha especificada.");
        }
    }
}
