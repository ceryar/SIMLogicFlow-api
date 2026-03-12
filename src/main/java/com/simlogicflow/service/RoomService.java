package com.simlogicflow.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.simlogicflow.dto.RoomDto;
import com.simlogicflow.model.Room;
import com.simlogicflow.repository.RoomRepository;

@Service
public class RoomService {

    @Autowired
    private RoomRepository roomRepository;

    public List<Room> getAllRooms() {
        return roomRepository.findAll();
    }

    public Room createRoom(RoomDto dto) {
        Room room = new Room();
        updateRoomFromDto(room, dto);
        return roomRepository.save(room);
    }

    public Room updateRoom(Long id, RoomDto dto) {
        Optional<Room> optionalRoom = roomRepository.findById(id);
        if (optionalRoom.isPresent()) {
            Room room = optionalRoom.get();
            updateRoomFromDto(room, dto);
            return roomRepository.save(room);
        }
        throw new RuntimeException("Room not found with id " + id);
    }

    public void deleteRoom(Long id) {
        roomRepository.deleteById(id);
    }

    private void updateRoomFromDto(Room room, RoomDto dto) {
        room.setName(dto.getName());
        room.setDescription(dto.getDescription());
        room.setCapacity(dto.getCapacity());
        room.setActive(dto.getActive());
    }
}
