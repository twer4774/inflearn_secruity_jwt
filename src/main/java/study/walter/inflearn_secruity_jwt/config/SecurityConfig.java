package study.walter.inflearn_secruity_jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@RequiredArgsConstructor
@Configuration
//@EnableWebSecurity // Spring Security Filter를 FilterChain에 등록
//public class SecurityConfig extends WebSecurityConfigurerAdapter { // WebSecurityConfigurerAdapter Deprecated 됨
public class SecurityConfig {


    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").hasRole("MANAGER")
                .antMatchers("/manager/**", "/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll();

        http
                .formLogin().loginPage("/loginForm"); // 권한이 없으면 로그인 페이지로 이동
                return http.build();
    }

}
