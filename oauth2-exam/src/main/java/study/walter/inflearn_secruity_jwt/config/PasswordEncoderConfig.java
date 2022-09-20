package study.walter.inflearn_secruity_jwt.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordEncoderConfig extends BCryptPasswordEncoder {

}
