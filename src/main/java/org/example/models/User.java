package org.example.models;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Builder
@ApiModel(description = "Model of user account data ")
@Component
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @ApiModelProperty(notes = "Unique id of user account")
    @Column
    private Long id;

    @ApiModelProperty(notes = "Account username")
    @Column
    private String username;

    @ApiModelProperty(notes = "User email address")
    @Column
    private String email;

    @ApiModelProperty(notes = "User password")
    @Column
    private String password;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

//    public User() {
//    }

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }
}