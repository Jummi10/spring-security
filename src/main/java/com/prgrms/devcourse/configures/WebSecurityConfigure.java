package com.prgrms.devcourse.configures;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}user123").roles("USER")
                .and()
                .withUser("admin01").password("{noop}admin123").roles("ADMIN")
                .and()
                .withUser("admin02").password("{noop}admin123").roles("ADMIN")
        ;
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers("/assets/**"); // 이 요청들에 대해서는 spring security 필터 체인을 적용하지 않겠다
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")    // 인증 영역 설정
                // isFullyAuthenticated(): rememberMe 통해서가 아닌 로그인 페이지에서 아이디, 패스워드를 입력해 인증된 사용자만 페이지에 접속 가능
                .antMatchers("/admin").access("hasRole('ADMIN') and isFullyAuthenticated() and oddAdmin")
                .anyRequest().permitAll()   // 익명 영역
                .expressionHandler(securityExpressionHandler())
                .and()

                .formLogin()
                .defaultSuccessUrl("/")
                // .loginPage("/my-login") // custom login page
                .usernameParameter("my-username")   // html page의 component name, default: username
                .passwordParameter("my-password")   // default: password
                .permitAll()
                .and()

                /**
                 * remeber me 설정
                 */
                .rememberMe()
                .key("my-remember-me")
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)  // 5분
                .and()

                /**
                 * 로그아웃 설정
                 */
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // default
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)    // default
                .clearAuthentication(true)  // default
                .and()

                /**
                 * HTTP 요청을 HTTPS 요청으로 리다이렉트, ChannelProcessingFilter
                 */
                .requiresChannel()
                .anyRequest().requiresSecure()  // 모든 요청은 https로 서비스해야한다(secure channel 요구)
                // .antMatchers("/api/**").requiresSecure()
                .and()

                .sessionManagement()
                .sessionFixation().changeSessionId()    // session fixation attack에 대한 전략 설정
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)   // session 생성 전략
                .invalidSessionUrl("/") // 유효하지 않은 세션 감지시 이동시킬 url
                .maximumSessions(1) // 최대 동시 로그인 가능한 session 개수
                .maxSessionsPreventsLogin(false)    // maximum session에 도달했을 경우
                .and()
                .and()

                /*.anonymous()
                .principal("thisIsAnonymousUser")  // default: anonymousUser
                .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")*/  // default: ROLE_ANONYMOUS

                /**
                 * 예외처리 핸들러
                 */
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
        ;
    }

    /**
     * customize AccessDeniedHandler
     * @return
     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (httpServletRequest, httpServletResponse, e) -> {
            Authentication authentication =
                    SecurityContextHolder.getContext().getAuthentication(); // AccessDeniedException을 발생시킨 사용자 정보
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpServletResponse.setContentType("text/plain");
            httpServletResponse.getWriter().write("## ACCESS DENIED ##");
            httpServletResponse.getWriter().flush();
            httpServletResponse.getWriter().close();
        };
    }

    public SecurityExpressionHandler<FilterInvocation> securityExpressionHandler() {
        return new CustomWebSecurityExpressionHandler(
                new AuthenticationTrustResolverImpl(),
                "ROLE_"
        );
    }
}
