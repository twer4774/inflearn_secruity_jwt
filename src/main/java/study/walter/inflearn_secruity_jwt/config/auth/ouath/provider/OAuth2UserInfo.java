package study.walter.inflearn_secruity_jwt.config.auth.ouath.provider;

public interface OAuth2UserInfo {
    String getProviderId();
    String getProvider();
    String getEmail();
    String getName();
}
