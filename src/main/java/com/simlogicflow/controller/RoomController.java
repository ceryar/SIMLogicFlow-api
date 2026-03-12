package com.simlogicflow.controller;

import com.simlogicflow.dto.RoomDto;
import com.simlogicflow.model.Room;
import com.simlogicflow.service.RoomService;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/rooms")
@PreAuthorize("hasAnyAuthority('ADMINISTRADOR', 'COORACAD')")
public class RoomController {

    @Autowired
    private RoomService roomService;

    @GetMapping
    public List<Room> getAllRooms() {
        return roomService.getAllRooms();
    }

    @PostMapping
    public Room createRoom(@RequestBody RoomDto dto) {
        return roomService.createRoom(dto);
    }

    @PutMapping("/{id}")
    public Room updateRoom(@PathVariable("id") Long id, @RequestBody RoomDto dto) {
        return roomService.updateRoom(id, dto);
    }

    @DeleteMapping("/{id}")
    public void deleteRoom(@PathVariable("id") Long id) {
        roomService.deleteRoom(id);
    }

}
