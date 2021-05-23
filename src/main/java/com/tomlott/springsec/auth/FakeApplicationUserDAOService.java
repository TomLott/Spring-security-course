package com.tomlott.springsec.auth;

import com.google.common.collect.Lists;
import com.tomlott.springsec.security.ApplicationUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;


@Repository("fake")
public class FakeApplicationUserDAOService implements ApplicationUserDAO{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDAOService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream().filter(a->a.getUsername().equals(username)).findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "annasmith",
                        true, true, true, true
                ),
                new ApplicationUser(
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "linda",
                        true, true, true, true
                ),
                new ApplicationUser(
                        ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "tom",
                        true, true, true, true
                )

        );
        return applicationUsers;
    }
}
