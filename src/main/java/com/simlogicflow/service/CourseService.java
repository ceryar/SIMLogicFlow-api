package com.simlogicflow.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.CourseDto;
import com.simlogicflow.model.Course;
import com.simlogicflow.model.Room;
import com.simlogicflow.model.Simulator;
import com.simlogicflow.repository.CourseRepository;
import com.simlogicflow.repository.RoomRepository;
import com.simlogicflow.repository.SimulatorRepository;

@Service
public class CourseService {

    @Autowired
    private CourseRepository courseRepository;

    @Autowired
    private RoomRepository roomRepository;

    @Autowired
    private SimulatorRepository simulatorRepository;

    public List<Course> getAllCourses() {
        return courseRepository.findAll();
    }

    public Course createCourse(CourseDto dto) {
        Course course = new Course();
        updateCourseFromDto(course, dto);
        return courseRepository.save(course);
    }

    public Course updateCourse(Long id, CourseDto dto) {
        Optional<Course> optionalCourse = courseRepository.findById(id);
        if (optionalCourse.isPresent()) {
            Course course = optionalCourse.get();
            updateCourseFromDto(course, dto);
            return courseRepository.save(course);
        }
        throw new RuntimeException("Course not found with id " + id);
    }

    public void deleteCourse(Long id) {
        courseRepository.deleteById(id);
    }

    private void updateCourseFromDto(Course course, CourseDto dto) {
        course.setName(dto.getName());
        course.setDescription(dto.getDescription());
        course.setFecInicio(dto.getFecInicio());
        course.setFecFin(dto.getFecFin());
        course.setHoras(dto.getHoras());

        if (dto.getRoomIds() != null && !dto.getRoomIds().isEmpty()) {
            java.util.List<Room> rooms = roomRepository.findAllById(dto.getRoomIds());
            course.setRooms(new java.util.HashSet<>(rooms));
        }

        if (dto.getSimulatorId() != null) {
            Simulator simulator = simulatorRepository.findById(dto.getSimulatorId())
                    .orElseThrow(() -> new RuntimeException("Simulator not found with id " + dto.getSimulatorId()));
            course.setSimulator(simulator);
        }
    }
}
