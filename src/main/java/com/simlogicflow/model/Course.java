package com.simlogicflow.model;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "courses")
public class Course {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 120)
    private String name;

    @Column(length = 255)
    private String description;

    @Column(name = "fec_inicio", nullable = false)
    private java.time.LocalDate fecInicio;

    @Column(name = "fec_fin", nullable = false)
    private java.time.LocalDate fecFin;

    @Column(name = "horas")
    private Integer horas;

    @ManyToMany
    @JoinTable(name = "course_rooms", joinColumns = @JoinColumn(name = "course_id"), inverseJoinColumns = @JoinColumn(name = "room_id"))
    private Set<Room> rooms;

    @ManyToOne
    @JoinColumn(name = "simulator_id", nullable = false)
    private Simulator simulator;

    @JsonIgnore
    @ManyToMany(mappedBy = "courses")
    private Set<User> users;

    @JsonIgnore
    @OneToMany(mappedBy = "course", cascade = jakarta.persistence.CascadeType.ALL, orphanRemoval = true)
    private java.util.List<ProCourse> proCourses;

}
