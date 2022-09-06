package study.walter.inflearn_secruity_jwt.config.auth;


import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import study.walter.inflearn_secruity_jwt.Model.User;
import study.walter.inflearn_secruity_jwt.repository.UserRepository;

/**
 * {@link study.walter.inflearn_secruity_jwt.config.SecurityConfig}에서 loginProcessingUrl("/login")과 관련
 * Spring Security에서는 login 요청이 들어오면 IoC에서는 UserDetailsService 타입의 loadUserByUsername 함수를 실행한다.
 */
@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User userEntity = userRepository.findByUsername(username);

        if(userEntity != null){
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
