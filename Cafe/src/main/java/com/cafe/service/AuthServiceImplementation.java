package com.cafe.service;

import com.cafe.dtos.SignupRequest;
import com.cafe.dtos.UserDto;
import com.cafe.entities.User;
import com.cafe.enums.UserRole;
import com.cafe.repository.UserRepo;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImplementation implements AuthService{


    private final UserRepo userRepo;


    public AuthServiceImplementation(UserRepo userRepo) {
        this.userRepo = userRepo;

    }                           //1

    @Override
    public UserDto createUser(SignupRequest signupRequest) {
        User user = new User();
        user.setName(signupRequest.getName());
        user.setEmail(signupRequest.getEmail());
        user.setPassword(new BCryptPasswordEncoder().encode(signupRequest.getPassword()));
        user.setUserRole(UserRole.CUSTOMER);
        User createdUser = userRepo.save(user);

        UserDto createuserDto = new UserDto();
        createuserDto.setId(createdUser.getId());
        createuserDto.setName(createdUser.getName());
        createuserDto.setEmail(createdUser.getEmail());
        createuserDto.setUserRole(createdUser.getUserRole());
        return createuserDto;
    }                                                                 //1
}
