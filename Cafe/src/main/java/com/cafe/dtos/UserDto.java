package com.cafe.dtos;

import com.cafe.enums.UserRole;
import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    private  int id;

    private String name;

    private String email;

    private String password;

    private UserRole userRole;
}
