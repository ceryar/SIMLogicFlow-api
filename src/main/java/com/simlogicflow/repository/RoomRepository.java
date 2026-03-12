package com.simlogicflow.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.simlogicflow.model.Room;

@Repository
public interface RoomRepository extends JpaRepository<Room, Long> {
}
