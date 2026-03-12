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

import com.simlogicflow.dto.ProCourseDto;
import com.simlogicflow.model.ProCourse;
import com.simlogicflow.service.ProCourseService;

@RestController
@RequestMapping("/api/v1/pro-courses")
@PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD', 'ESTUDIANTE', 'INSTRUCTOR', 'PSEUDOPILOTO', 'TECNICO')")
public class ProCourseController {

    @Autowired
    private ProCourseService proCourseService;

    @GetMapping
    public List<ProCourse> getAllProCourses() {
        return proCourseService.getAllProCourses();
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public ProCourse createProCourse(@RequestBody ProCourseDto dto) {
        return proCourseService.createProCourse(dto);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public ProCourse updateProCourse(@PathVariable("id") Long id, @RequestBody ProCourseDto dto) {
        return proCourseService.updateProCourse(id, dto);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public void deleteProCourse(@PathVariable("id") Long id) {
        proCourseService.deleteProCourse(id);
    }

}
