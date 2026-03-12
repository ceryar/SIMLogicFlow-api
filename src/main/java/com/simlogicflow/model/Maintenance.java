package com.simlogicflow.model;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.Set;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
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
@Table(name = "maintenances")
public class Maintenance {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 255)
    private String description;

    @Column(name = "fec_ini")
    private LocalDate fecIni;

    @Column(name = "fec_fin")
    private LocalDate fecFin;

    @Column(name = "hora_ini", nullable = false)
    private LocalTime horaIni;

    @Column(name = "hora_fin", nullable = false)
    private LocalTime horaFin;

    @ManyToOne
    @JoinColumn(name = "simulator_id", nullable = false)
    private Simulator simulator;

    @ManyToOne
    @JoinColumn(name = "maintenance_type_id")
    private MaintenanceType maintenanceType;
    @OneToMany(mappedBy = "maintenance")
    private Set<MaintenanceHistory> history;

}
