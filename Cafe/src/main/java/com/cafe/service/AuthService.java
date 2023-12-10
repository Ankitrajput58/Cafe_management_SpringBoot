package com.cafe.service;

import com.cafe.dtos.SignupRequest;
import com.cafe.dtos.UserDto;
import com.cafe.entities.User;
import com.cafe.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.codec.json.AbstractJackson2Encoder;
import org.springframework.stereotype.Service;


public interface AuthService {
    UserDto createUser(SignupRequest signupRequest);  //1
}
