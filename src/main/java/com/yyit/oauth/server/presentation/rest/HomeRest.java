package com.yyit.oauth.server.presentation.rest;

import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <p>
 * 此处为功能说明
 * </p>
 *
 * @author yanpingping
 * @date 2022/4/13
 **/
@RestController
public class HomeRest {

    @GetMapping
    public String index(){
        return "Hello!";
    }

    @GetMapping("/private")
    public HttpEntity privateN(){
        return  ResponseEntity.ok("private string") ;
    }

}
