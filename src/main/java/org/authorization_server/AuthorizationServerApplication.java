package org.authorization_server;

import jakarta.annotation.PostConstruct;
import org.authorization_server.model.User;
import org.authorization_server.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class AuthorizationServerApplication {
//    @Autowired
//    private UserService userService;
//    @PostConstruct
//    public void createUser(){
//        List<String> auth = new ArrayList<>();
//        auth.add("READ");
//        auth.add("WRITE");
//        auth.add("DELETE");
//        auth.add("UPDATE");
//        userService.save(new User(0,"Hakim","Hakim@123",auth));
//    }
    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }
}
