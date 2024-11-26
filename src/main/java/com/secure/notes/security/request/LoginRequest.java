package com.secure.notes.security.request;

import lombok.Getter;
import lombok.Setter;

//This class is defining the format on how the request to be send
@Setter
@Getter
public class LoginRequest {
    private String username;

    private String password;

}