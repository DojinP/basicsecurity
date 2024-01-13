package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(
                        auth -> auth
                                .anyRequest()       // 모든 요청에 대해
                                .authenticated()    // 인증된 사용자에게 접근을 허용
                );

        http.formLogin(
                login -> login
                        .loginPage("/login")    // 로그인이 필요한 경우 사용자에게 보낼 URL 을 지정
                        .defaultSuccessUrl("/") // 인증 성공할 경우 redirection 될 URL 을 지정
                        .failureUrl("/login")   // 인증 실패할 경우 사용자에게 보낼 URL 을 지정 (기본 값 : "/login?error")
                        .usernameParameter("userId")    // 인증 수행 시 사용자 이름을 찾기 위한 HTTP 파라미터. (기본 값 : "username")
                        .passwordParameter("passWd")    // 인증 수행 시 비밀번호을 찾기 위한 HTTP 파라미터. (기본 값 : "password")
                        .loginProcessingUrl("/login_proc")  // 자격 증명의 유효성을 검사할 URL 을 지정
                        .successHandler((request, response, authentication) -> {    // 인증 성공 시 동작하는 Handler (기본 값 : 'SavedRequestAwareAuthenticationSuccessHandler')
                            System.out.println("authentication " + authentication.getName());
                            response.sendRedirect("/");
                        })
                        .failureHandler((request, response, exception) -> { // 인증 실패 시 동작하는 Handler (기본 값 : 'SimpleUrlAuthenticationFailureHandler' 를 통해 "/login?error" 로 redirection)
                            System.out.println("exception " + exception.getMessage());
                            response.sendRedirect("/login");
                        })
                        .permitAll() // 모든 login page 에 대한 접근을 허용
        );

        return http.build();
    }
}
