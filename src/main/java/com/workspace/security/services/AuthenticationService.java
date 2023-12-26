package com.workspace.security.services;

import com.workspace.security.commons.vo.requests.AuthenticationRequestVo;
import com.workspace.security.commons.vo.responses.AuthenticationResponseVo;
import com.workspace.security.commons.vo.requests.RegisterRequestVo;
import com.workspace.security.persistence.entity.User;
import com.workspace.security.persistence.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponseVo register(RegisterRequestVo request) {

        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        repository.save(user);
        var jwt = jwtService.generateToken(user);
        return AuthenticationResponseVo.builder()
                .token(jwt)
                .build();
    }

    public AuthenticationResponseVo authenticate(AuthenticationRequestVo request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail(), request.getPassword()
        ));
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwt = jwtService.generateToken(user);
        return AuthenticationResponseVo.builder()
                .token(jwt)
                .build();
    }
}
