package org.example.controllers;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.example.models.ERole;
import org.example.models.User;
import org.example.repository.RoleRepository;
import org.example.repository.UserRepository;
import org.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@Api(tags = "Retrieve Information Controller", description = "Controller uses accessing protected resource methods with role based validations.")
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @GetMapping("/all")
    @ApiOperation(value = "Finds all user accounts status info",
            notes = "Returns the entire list of user accounts",
            response = User.class, responseContainer = "List")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The request has succeeded", response = User.class, responseContainer = "List"),
            @ApiResponse(code = 401, message = "The request requires user authentication"),
            @ApiResponse(code = 403, message = "Accessing the resource you were trying to reach is forbidden"),
            @ApiResponse(code = 404, message = "The server has not found anything matching the Request-URI"),
            @ApiResponse(code = 500, message = "Server error")})
        public ResponseEntity<List<User>> findAllUsers(Model theModel) {
            List<User> userList = userService.findAll();
            return ResponseEntity.ok(userList);
        }

    //TODO: correction needed
    @GetMapping("/user")
    @ApiOperation(value = "Finds user account",
            notes = "Returns user account",
            response = User.class, responseContainer = "List")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The request has succeeded", response = User.class, responseContainer = "List"),
            @ApiResponse(code = 401, message = "The request requires user authentication"),
            @ApiResponse(code = 403, message = "Accessing the resource you were trying to reach is forbidden"),
            @ApiResponse(code = 404, message = "The server has not found anything matching the Request-URI"),
            @ApiResponse(code = 500, message = "Server error")})
//    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<List<User>> getByUsername(@RequestParam String username) {
        List<User> userList = userRepository.findByUsername(username);
        return ResponseEntity.ok(userList);
    }

    //TODO: correction needed
    @GetMapping("/allUsers")
    @ApiOperation(value = "Finds all user accounts status info",
            notes = "Returns the entire list of user accounts",
            response = User.class, responseContainer = "List")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The request has succeeded", response = User.class, responseContainer = "List"),
            @ApiResponse(code = 401, message = "The request requires user authentication"),
            @ApiResponse(code = 403, message = "Accessing the resource you were trying to reach is forbidden"),
            @ApiResponse(code = 404, message = "The server has not found anything matching the Request-URI"),
            @ApiResponse(code = 500, message = "Server error")})
    public ResponseEntity<List<User>> getByRoleUsers(@RequestParam ERole name) {
        List<User> userList = roleRepository.findByNameIs(ERole.ROLE_USER);
        return ResponseEntity.ok(userList);
    }

    //TODO: correction needed
    @GetMapping("/mod")
    @ApiOperation(value = "Finds all moderator account status info",
            notes = "Returns the entire list of moderator accounts",
            response = User.class, responseContainer = "List")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The request has succeeded", response = User.class, responseContainer = "List"),
            @ApiResponse(code = 401, message = "The request requires user authentication"),
            @ApiResponse(code = 403, message = "Accessing the resource you were trying to reach is forbidden"),
            @ApiResponse(code = 404, message = "The server has not found anything matching the Request-URI"),
            @ApiResponse(code = 500, message = "Server error")})
//    @PreAuthorize("hasRole('MODERATOR')")
        public ResponseEntity<List<User>> getByRoleModerators(@RequestParam ERole name) {
            List<User> userList = roleRepository.findByNameIs(ERole.ROLE_MODERATOR);
            return ResponseEntity.ok(userList);
        }

    //TODO: correction needed
    @GetMapping("/admin")
    @ApiOperation(value = "Finds all administrator account status info",
            notes = "Returns the entire list of administrator accounts",
            response = User.class, responseContainer = "List")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The request has succeeded", response = User.class, responseContainer = "List"),
            @ApiResponse(code = 401, message = "The request requires user authentication"),
            @ApiResponse(code = 403, message = "Accessing the resource you were trying to reach is forbidden"),
            @ApiResponse(code = 404, message = "The server has not found anything matching the Request-URI"),
            @ApiResponse(code = 500, message = "Server error")})
//    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getByRoleAdmins(@RequestParam ERole name) {
        List<User> userList = roleRepository.findByNameIs(ERole.ROLE_ADMIN);
        return ResponseEntity.ok(userList);
    }
}