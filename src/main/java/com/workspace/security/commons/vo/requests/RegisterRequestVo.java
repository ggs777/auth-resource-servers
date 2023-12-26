package com.workspace.security.commons.vo.requests;

import com.workspace.security.commons.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequestVo {

    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private Role role;
}
