package com.quidcash.quidapp.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;


@RestController
@RequestMapping("/")
public class HealthCheck {
    
    @GetMapping("/ping")
    public String ping() {
        return "Pong";
    }
    
}
