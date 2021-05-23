package com.tomlott.springsec.auth;

import org.springframework.stereotype.Component;

import java.util.Optional;

public interface ApplicationUserDAO {

    public Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
