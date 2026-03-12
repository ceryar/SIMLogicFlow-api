package com.simlogicflow.dto;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class MaintenanceHistoryDto {

    private String observation;
    private LocalDateTime changeDate;
    private Long maintenanceId;

}
