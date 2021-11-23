package com.prgrms.devcourse.configures;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}user123").roles("USER")
                .and()
                .withUser("admin").password("{noop}admin123").roles("ADMIN")
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
                .anyRequest().permitAll()   // 익명 영역
                .and()

                .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()

                /**
                 * remeber me 설정
                 */
                .rememberMe()
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
                /*.and()

                .anonymous()
                .principal("thisIsAnonymousUser")  // default: anonymousUser
                .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")*/  // default: ROLE_ANONYMOUS
        ;
    }
}
