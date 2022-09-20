package study.walter.inflearn_secruity_jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.walter.inflearn_secruity_jwt.Model.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    User findByUsername(String username);

}
