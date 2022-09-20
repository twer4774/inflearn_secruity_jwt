package study.walter.inflearn_secruity_jwt.config.auth;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import study.walter.inflearn_secruity_jwt.Model.User;

import javax.annotation.sql.DataSourceDefinitions;
import java.util.ArrayList;
import java.util.Collection;

/** 소스 참고용으로만 볼 것. 일반로그인, SNS 로그인 통합은 PrincipalDetailsIntegration에서 함
 * Security가 /login 주소 요청이 들어오면 로그인을 진행시킨다.
 * 로그인이 진행되면 Security의 Session을 만들어 낸다. (Seucrity ContextHolder)
 * Securrity ContextHolder에는 Authentication 객체가 들어간다.
 *  - Authentication 안에는 User 정보 등이 들어간다.
 *  - User 객체의 타입은 UserDetails 타입의 객체가 들어간다.
 *
 *  Seucrity Session => Authentication(PrincipalDetailsService) => UserDetails(PrincipalDetails)
 */

@Data
public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    /**
     * 해당 User의 권한 리턴
     * @return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        /*
        // 1년간 로그인 안한 회원인 경우 -> 휴면회원
        // 현재 시간 - 로그인 시간 => 1년 초과시 false
        if(LocalDateTime.now() - user.getLoginDate() > 365) return false;
        */

        return true;
    }
}
