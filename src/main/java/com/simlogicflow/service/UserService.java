package com.simlogicflow.service;

import com.simlogicflow.dto.UserDto;
import com.simlogicflow.model.Course;
import com.simlogicflow.model.DocumentType;
import com.simlogicflow.model.Role;
import com.simlogicflow.model.User;
import com.simlogicflow.repository.CourseRepository;
import com.simlogicflow.repository.DocumentTypeRepository;
import com.simlogicflow.repository.RolRepository;
import com.simlogicflow.repository.UserRepository;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private RolRepository rolRepository;

        @Autowired
        private DocumentTypeRepository documentTypeRepository;

        @Autowired
        private CourseRepository courseRepository;

        public User save(UserDto userDto) {

                Role role = rolRepository.findById(userDto.getRoleId())
                                .orElseThrow(() -> new RuntimeException("Role not found"));

                DocumentType documentType = documentTypeRepository
                                .findById(userDto.getDocumentTypeId())
                                .orElseThrow(() -> new RuntimeException("Document type not found"));

                // Generate default password: FirstCharOfFirstName + docNumber +
                // FirstCharOfLastName
                String firstName = userDto.getFirstName();
                String lastName = userDto.getLastname();
                String docNum = userDto.getDocumentNumber();

                String defaultPassword = (firstName != null && !firstName.isEmpty()
                                ? firstName.substring(0, 1).toUpperCase()
                                : "")
                                + (docNum != null ? docNum : "")
                                + (lastName != null && !lastName.isEmpty() ? lastName.substring(0, 1).toUpperCase()
                                                : "");

                User user = User.builder()
                                .firstName(userDto.getFirstName())
                                .middleName(userDto.getMiddleName())
                                .lastname(userDto.getLastname())
                                .secondlasname(userDto.getSecondlasname())
                                .email(userDto.getEmail())
                                .password(passwordEncoder.encode(defaultPassword))
                                .active(userDto.getActive())
                                .documentNumber(userDto.getDocumentNumber())
                                .documentType(documentType)
                                .role(role)
                                .mustChangePassword(true)
                                .build();

                return userRepository.save(user);

        }

        public java.util.List<User> getAllUsers() {
                return userRepository.findAll();
        }

        public User updateUser(Long id, UserDto userDto) {
                User user = userRepository.findById(id)
                                .orElseThrow(() -> new RuntimeException("User not found"));

                if (userDto.getRoleId() != null) {
                        Role role = rolRepository.findById(userDto.getRoleId())
                                        .orElseThrow(() -> new RuntimeException("Role not found"));
                        user.setRole(role);
                }

                if (userDto.getDocumentTypeId() != null) {
                        DocumentType documentType = documentTypeRepository
                                        .findById(userDto.getDocumentTypeId())
                                        .orElseThrow(() -> new RuntimeException("Document type not found"));
                        user.setDocumentType(documentType);
                }

                user.setFirstName(userDto.getFirstName());
                user.setMiddleName(userDto.getMiddleName());
                user.setLastname(userDto.getLastname());
                user.setSecondlasname(userDto.getSecondlasname());
                user.setEmail(userDto.getEmail());

                if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
                        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
                }

                user.setActive(userDto.getActive());
                user.setDocumentNumber(userDto.getDocumentNumber());

                return userRepository.save(user);
        }

        public void deleteUser(Long id) {
                User user = userRepository.findById(id)
                                .orElseThrow(() -> new RuntimeException("User not found"));
                userRepository.delete(user);
        }

        public User assignCourseToUser(Long userId, Long courseId) {
                User user = userRepository.findById(userId)
                                .orElseThrow(() -> new RuntimeException("User not found"));

                Course course = courseRepository.findById(courseId)
                                .orElseThrow(() -> new RuntimeException("Course not found"));

                validateCourseCapacity(course, user);

                user.getCourses().add(course);
                return userRepository.save(user);
        }

        private void validateCourseCapacity(Course course, User userToAdd) {
                String roleName = userToAdd.getRole().getName().toLowerCase();
                boolean isStudent = roleName.contains("estudiante") || roleName.contains("student");
                boolean isInstructor = roleName.contains("instructor");
                boolean isPseudopilot = roleName.contains("pseudo");

                if (!isStudent && !isInstructor && !isPseudopilot) {
                        return; // We only check capacities for these specific roles
                }

                int maxStudents = 0;
                int maxInstructors = 0;
                int maxPseudopilots = 0;

                String simName = course.getSimulator() != null ? course.getSimulator().getName().toLowerCase() : "";
                boolean isIndra = simName.contains("indra");
                boolean isThales = simName.contains("thales");

                if (course.getRooms() != null) {
                        for (com.simlogicflow.model.Room room : course.getRooms()) {
                                String roomName = room.getName().toLowerCase();

                                if (isIndra) {
                                        if (roomName.contains("radar")) {
                                                maxStudents += 10;
                                                maxInstructors += 5;
                                        } else if (roomName.contains("aeródromo") || roomName.contains("aerodromo")) {
                                                maxStudents += 8;
                                                maxInstructors += 5;
                                        } else if (roomName.contains("pseudo")) {
                                                maxPseudopilots += 10;
                                        }
                                } else if (isThales) {
                                        if (roomName.contains("radar")) {
                                                maxStudents += 10;
                                                maxInstructors += 5;
                                        } else if (roomName.contains("aeródromo") || roomName.contains("aerodromo")) {
                                                maxStudents += 8;
                                                maxInstructors += 5;
                                        } else if (roomName.contains("pseudo")) {
                                                maxPseudopilots += 12;
                                        }
                                }
                        }
                }

                // Count current users by role
                int currentStudents = 0;
                int currentInstructors = 0;
                int currentPseudopilots = 0;

                if (course.getUsers() != null) {
                        for (User u : course.getUsers()) {
                                String rName = u.getRole().getName().toLowerCase();
                                if (rName.contains("estudiante") || rName.contains("student"))
                                        currentStudents++;
                                else if (rName.contains("instructor"))
                                        currentInstructors++;
                                else if (rName.contains("pseudo"))
                                        currentPseudopilots++;
                        }
                }

                if (isStudent && (currentStudents + 1) > maxStudents) {
                        throw new com.simlogicflow.exceptions.CapacityExceededException(
                                        "Se ha excedido la capacidad máxima de estudiantes (" + maxStudents
                                                        + ") para las salas asignadas.");
                }
                if (isInstructor && (currentInstructors + 1) > maxInstructors) {
                        throw new com.simlogicflow.exceptions.CapacityExceededException(
                                        "Se ha excedido la capacidad máxima de instructores (" + maxInstructors
                                                        + ") para las salas asignadas.");
                }
                if (isPseudopilot && (currentPseudopilots + 1) > maxPseudopilots) {
                        throw new com.simlogicflow.exceptions.CapacityExceededException(
                                        "Se ha excedido la capacidad máxima de pseudopilotos (" + maxPseudopilots
                                                        + ") para las salas asignadas.");
                }
        }

        public User removeCourseFromUser(Long userId, Long courseId) {
                User user = userRepository.findById(userId)
                                .orElseThrow(() -> new RuntimeException("User not found"));

                Course course = courseRepository.findById(courseId)
                                .orElseThrow(() -> new RuntimeException("Course not found"));

                user.getCourses().remove(course);
                return userRepository.save(user);
        }

        public Set<Course> getCoursesByUser(Long userId) {
                User user = userRepository.findById(userId)
                                .orElseThrow(() -> new RuntimeException("User not found"));
                return user.getCourses();
        }

        public void changePassword(Long userId, String newPassword) {
                User user = userRepository.findById(userId)
                                .orElseThrow(() -> new RuntimeException("User not found"));
                user.setPassword(passwordEncoder.encode(newPassword));
                user.setMustChangePassword(false);
                userRepository.save(user);
        }
}
