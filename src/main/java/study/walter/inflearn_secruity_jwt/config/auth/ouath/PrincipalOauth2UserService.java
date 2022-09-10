package study.walter.inflearn_secruity_jwt.config.auth.ouath;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import study.walter.inflearn_secruity_jwt.Model.User;
import study.walter.inflearn_secruity_jwt.config.PasswordEncoderConfig;
import study.walter.inflearn_secruity_jwt.config.auth.PrincipalDetailsIntegration;
import study.walter.inflearn_secruity_jwt.repository.UserRepository;

import java.util.Map;

@RequiredArgsConstructor
@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {


    private final UserRepository userRepository;

    private final PasswordEncoderConfig passwordEncoder;

    // SNS 로그인으로 부터 받은 userRequest 데이터에 대한 후처리 함수
    // 함수 종료 시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println(userRequest.getClientRegistration());
        System.out.println(userRequest.getAccessToken());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // SNS 로그인 -> 로그인 창 -> 로그인 완료 -> Code를 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
        // userRequest 정보 -> loadUser 함수 호출 -> SNS 회원프로필 리턴
        System.out.println("getAttributes " + oAuth2User.getAttributes());

        // 강제 회원가입 진행
        String provider = userRequest.getClientRegistration().getClientId(); // google
        String providerId = oAuth2User.getAttribute("sub");
        String username = provider +"_" + providerId; // 중복피하기
        String password = passwordEncoder.encode("aaa");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null){
            userEntity  = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            userRepository.save(userEntity);
        }

//        return super.loadUser(userRequest);
        return new PrincipalDetailsIntegration(userEntity, oAuth2User.getAttributes());
    }
}
