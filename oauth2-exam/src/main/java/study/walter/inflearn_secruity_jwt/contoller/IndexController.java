package study.walter.inflearn_secruity_jwt.contoller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import study.walter.inflearn_secruity_jwt.Model.User;
import study.walter.inflearn_secruity_jwt.config.auth.PrincipalDetails;
import study.walter.inflearn_secruity_jwt.config.auth.PrincipalDetailsIntegration;
import study.walter.inflearn_secruity_jwt.repository.UserRepository;

/*
주의! PrincipalDetails는 참고용으로만 볼것
PrincipalDetailsIntegration에서 일반로그인과 SNS로그인이 통합됨
 */
@RequiredArgsConstructor
@Controller //View를 리턴한다.
public class IndexController {


    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    /* ============================ 일반로그인과 SNS로그인 분리================================================== *//*

    *//*
    PrincipalDetails에서 UserDetails를 구현하고 있으므로 접근 가능하다.
    UserDetails는 일반 로그인(SNS로그인이 아닌)을 할때 사용한다.
    *//*
    @GetMapping("/test/login")
    public @ResponseBody
    String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) {
        System.out.println("/text/login ------------- ");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        System.out.println("authentication : " + principalDetails.getUser());

        System.out.println("userDetails : " + userDetails.getUser());

        return "confirm session info";
    }

    *//*
    단순 DI로 접근하는지(Authentication), 어노테이션으로 접근하는지(@AuthenticationPrincipal) 선택하여 사용가능하다.
    OAuth2User 객체는 SNS로그인에서 사용 가능하다.
    // 이때, 일반로그인과 SNS로그인을 하나로 통합하는 과정이 필요하다. => 클래스를 하나 만들어, UerDetails와 OAuth2Uer를 구현하여 Authentication에 넣는다.
     *//*
    @GetMapping("/test/oauth/login")
    public @ResponseBody
    String testLogin(Authentication authentication,
                     @AuthenticationPrincipal OAuth2User oauth) {
        System.out.println("/text/login ------------- ");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        System.out.println("authentication : " + oAuth2User.getAttributes());
        System.out.println("oauth2User " + oauth.getAttributes());


        return "oauth2 confirm session info";
    }*/


    /* ============================ 일반로그인과 SNS로그인 통합================================================== */
    @GetMapping("/user2")
    public @ResponseBody String user2(@AuthenticationPrincipal PrincipalDetailsIntegration principalDetails) {

        System.out.println(principalDetails);
        System.out.println("principalDetailsIntegration : " + principalDetails.getUser());
        return "user2";
    }



    @GetMapping({"", "/"})
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(){
        return "user";
    }


    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public  String join(User user){


        user.setRole("ROLE_USER");

        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "redirect:/loginForm";
    }


    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";

    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "dataInfo";

    }

}
