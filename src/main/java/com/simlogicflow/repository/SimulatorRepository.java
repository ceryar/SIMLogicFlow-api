package com.simlogicflow.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.simlogicflow.model.Simulator;

@Repository
public interface SimulatorRepository extends JpaRepository<Simulator, Long> {
}
