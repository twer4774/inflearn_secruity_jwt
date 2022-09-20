package study.walter.inflearn_secruity_jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import study.walter.inflearn_secruity_jwt.config.auth.ouath.PrincipalOauth2UserService;

/**
 * 일반적인 SNS 인증 및 인가 흐름 정리
 1. 코드 받기 (인증)
 2. 액세스토큰 (권한)
 3. 사용자 프로필 정보 가져오기 (액세스 토큰 이용)
 4. 3의 정보로 회원가입 등의 서비스 로직 실행

 * Oauth2-Client 라이브러리를 사용했을 때
  인가 코드를 반환받는 것이 아닌, 액세스 토큰 + 사용자 정보를 한 번에 받아온다.
 */

@RequiredArgsConstructor
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // @Secured 어노테이션 활성화, @PreAuthorize&인PostAuthorize 어노테이션 활성화
//@EnableWebSecurity // Spring Security Filter를 FilterChain에 등록
//public class SecurityConfig extends WebSecurityConfigurerAdapter { // WebSecurityConfigurerAdapter Deprecated 됨
public class SecurityConfig {


    private final PrincipalOauth2UserService principalOauth2UserService;
//    @Bean
//    public BCryptPasswordEncoder encodePwd(){
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().permitAll();

        http
                .formLogin()
                .loginPage("/loginForm") // 권한이 없으면 로그인 페이지로 이동
                .usernameParameter("username")
                .loginProcessingUrl("/login") // '/login' 주소가 호출이 되면 시큐리티가 대신 로그인해준다.
                .defaultSuccessUrl("/");

        http.oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService);

                return http.build();
    }

}
