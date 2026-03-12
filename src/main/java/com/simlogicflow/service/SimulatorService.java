package com.simlogicflow.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.SimulatorDto;
import com.simlogicflow.model.Simulator;
import com.simlogicflow.repository.SimulatorRepository;

@Service
public class SimulatorService {

    @Autowired
    private SimulatorRepository simulatorRepository;

    public List<Simulator> getAllSimulators() {
        return simulatorRepository.findAll();
    }

    public Simulator createSimulator(SimulatorDto dto) {
        Simulator simulator = new Simulator();
        updateSimulatorFromDto(simulator, dto);
        return simulatorRepository.save(simulator);
    }

    public Simulator updateSimulator(Long id, SimulatorDto dto) {
        Optional<Simulator> optionalSimulator = simulatorRepository.findById(id);
        if (optionalSimulator.isPresent()) {
            Simulator simulator = optionalSimulator.get();
            updateSimulatorFromDto(simulator, dto);
            return simulatorRepository.save(simulator);
        }
        throw new RuntimeException("Simulator not found with id " + id);
    }

    public void deleteSimulator(Long id) {
        simulatorRepository.deleteById(id);
    }

    private void updateSimulatorFromDto(Simulator simulator, SimulatorDto dto) {
        simulator.setName(dto.getName());
        simulator.setDescription(dto.getDescription());
        simulator.setActive(dto.getActive());
    }
}
