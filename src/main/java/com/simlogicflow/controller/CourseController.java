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

import com.simlogicflow.dto.CourseDto;
import com.simlogicflow.model.Course;
import com.simlogicflow.service.CourseService;

@RestController
@RequestMapping("/api/v1/courses")
@PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD', 'ESTUDIANTE', 'INSTRUCTOR', 'PSEUDOPILOTO', 'TECNICO')")
public class CourseController {

    @Autowired
    private CourseService courseService;

    @GetMapping
    public List<Course> getAllCourses() {
        return courseService.getAllCourses();
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public Course createCourse(@RequestBody CourseDto dto) {
        return courseService.createCourse(dto);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public Course updateCourse(@PathVariable("id") Long id, @RequestBody CourseDto dto) {
        return courseService.updateCourse(id, dto);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public void deleteCourse(@PathVariable("id") Long id) {
        courseService.deleteCourse(id);
    }

}
