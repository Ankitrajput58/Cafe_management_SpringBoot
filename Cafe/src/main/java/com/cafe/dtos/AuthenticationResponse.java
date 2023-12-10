package com.cafe.dtos;

import com.cafe.enums.UserRole;
import com.cafe.repository.UserRepo;
import lombok.Data;

@Data
public class AuthenticationResponse {
    private String jwt;
    private UserRole userRole;
    private int userId;
}
