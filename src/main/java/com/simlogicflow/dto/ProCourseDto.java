package com.simlogicflow.dto;

import java.time.LocalDate;
import java.time.LocalTime;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ProCourseDto {

    private LocalTime horaini;
    private LocalTime horafin;
    private Integer horas;
    private LocalDate fecha;
    private Long courseId;

}
