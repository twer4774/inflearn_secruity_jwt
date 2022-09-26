
package study.walter.inflearn_security_jwt.jwt;

/*

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.walter.inflearn_security_jwt.auth.PrincipalDetails;
import study.walter.inflearn_security_jwt.model.User;
import study.walter.inflearn_security_jwt.repository.UserRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링시큐리티에셔 UsernamePasswordAuthenticationFilter가 있다.
// login 요청에서 username, password 전송하면 UsernamePasswordAuthenticationFilter가 동작함

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    // login 요청 시 실행되는 함수
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        System.out.println("JWTAuthenticationFilter 로그인 시도중");

        // 1. username, password를 받는다.
        try{
*/
/*BufferedReader br = request.getReader();

            String input = null;
            while((input = br.readLine()) != null){
                System.out.println(input);
            }*//*



            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            // 정상이면 authentication이 리턴된다
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session 영역 저장 -> 로그인이 되었다.
            // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 된다.
            // 리턴의 융: 권한 관리를 security가 대신 해주기 때문에 편하다. -> 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없다. 단지 권한 처리 때문에 session이 필요하다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());

            return authentication;
        } catch (IOException e){
            e.printStackTrace();
        }

        return null;
    }



*/
/**
     * {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse)} 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 ㅈ실행된다.
     * JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response해준다.
     *//*


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("walter"));


        response.addHeader("Authorization", "Bearer " + jwtToken);
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
*/


import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import study.walter.inflearn_security_jwt.auth.PrincipalDetails;
import study.walter.inflearn_security_jwt.model.User;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

    private final AuthenticationManager authenticationManager;

    // Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
    // 인증 요청시에 실행되는 함수 => /login
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter : 진입");


        try {
            // request에 있는 username과 password를 파싱해서 자바 Object로 받기
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨
            // 정상이면 authentication이 리턴된다
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session 영역 저장 -> 로그인이 되었다.
            // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 된다.
            // 리턴의 융: 권한 관리를 security가 대신 해주기 때문에 편하다. -> 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없다. 단지 권한 처리 때문에 session이 필요하다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            return authentication;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // JWT Token 생성해서 response에 담아주기
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("walter"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }

}

