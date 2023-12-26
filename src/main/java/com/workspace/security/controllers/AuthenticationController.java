package com.workspace.security.controllers;

import com.workspace.security.commons.vo.requests.AuthenticationRequestVo;
import com.workspace.security.commons.vo.responses.AuthenticationResponseVo;
import com.workspace.security.services.AuthenticationService;
import com.workspace.security.commons.vo.requests.RegisterRequestVo;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponseVo> register(
            @RequestBody RegisterRequestVo request
    ){
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponseVo> authenticate(
            @RequestBody AuthenticationRequestVo request
    ){
        return ResponseEntity.ok(service.authenticate(request));
    }
}
