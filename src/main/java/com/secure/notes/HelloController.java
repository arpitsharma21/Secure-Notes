package com.secure.notes;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.processing.Generated;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String home(){
        return "Hello";
    }

    @GetMapping("/contact")
    public String contact(){
        return "contact";
    }
}
