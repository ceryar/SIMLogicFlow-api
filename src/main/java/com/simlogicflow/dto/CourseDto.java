package com.simlogicflow.dto;

import java.time.LocalDate;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CourseDto {

    private String name;
    private String description;
    private LocalDate fecInicio;
    private LocalDate fecFin;
    private Integer horas;
    private java.util.List<Long> roomIds;
    private Long simulatorId;

}
