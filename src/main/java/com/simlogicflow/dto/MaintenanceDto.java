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
public class MaintenanceDto {

    private String description;
    private LocalDate fecIni;
    private LocalDate fecFin;
    private LocalTime horaIni;
    private LocalTime horaFin;
    private Long simulatorId;
    private Long maintenanceTypeId;

}
