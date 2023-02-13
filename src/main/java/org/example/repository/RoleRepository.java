package org.example.repository;

import org.example.models.ERole;
import org.example.models.Role;
import org.example.models.User;
import org.example.repository.model.RoleDAO;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleRepository extends JpaRepository<RoleDAO, Long> {

    //TODO: correct if needed
    List<User> findByNameIs(ERole name);

    Role findByName(ERole name);
}