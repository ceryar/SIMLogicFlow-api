package com.simlogicflow.controller;

import com.simlogicflow.dto.UserDto;
import com.simlogicflow.model.User;
import com.simlogicflow.service.UserService;
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

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public java.util.List<User> getAllUsers() {
        return userService.getAllUsers();
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public User createUser(@RequestBody UserDto dto) {
        return userService.save(dto);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public User updateUser(@PathVariable("id") Long id, @RequestBody UserDto dto) {
        return userService.updateUser(id, dto);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public void deleteUser(@PathVariable("id") Long id) {
        userService.deleteUser(id);
    }

    @PostMapping("/{userId}/courses")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public User assignCourseToUser(@PathVariable("userId") Long userId,
            @RequestBody com.simlogicflow.dto.UserCourseDto dto) {
        return userService.assignCourseToUser(userId, dto.getCourseId());
    }

    @DeleteMapping("/{userId}/courses/{courseId}")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
    public User removeCourseFromUser(@PathVariable("userId") Long userId, @PathVariable("courseId") Long courseId) {
        return userService.removeCourseFromUser(userId, courseId);
    }

    @GetMapping("/{userId}/courses")
    @PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD', 'ESTUDIANTE', 'INSTRUCTOR', 'PSEUDOPILOTO')")
    public java.util.Set<com.simlogicflow.model.Course> getCoursesByUser(@PathVariable("userId") Long userId) {
        return userService.getCoursesByUser(userId);
    }

    @PutMapping("/{id}/change-password")
    public void changePassword(@PathVariable("id") Long id, @RequestBody java.util.Map<String, String> body) {
        String newPassword = body.get("newPassword");
        userService.changePassword(id, newPassword);
    }
}
