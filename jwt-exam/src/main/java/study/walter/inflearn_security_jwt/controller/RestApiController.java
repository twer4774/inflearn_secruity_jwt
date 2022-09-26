package study.walter.inflearn_security_jwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import study.walter.inflearn_security_jwt.model.User;
import study.walter.inflearn_security_jwt.repository.UserRepository;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("home")
    public String home() {
        return "<h1>home</h1>";
    }


    @PostMapping("token")
    public String token() {
        return "<h1>token</h1>";
    }


    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    @GetMapping("/api/v1/user")
    public String user(Authentication authentication){
        System.out.println("auth " +
                authentication);
        return "user";
    }

    // manager, admin
    @GetMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }

    // admin
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "admin";
    }


}
