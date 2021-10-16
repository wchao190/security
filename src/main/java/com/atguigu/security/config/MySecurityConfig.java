package com.atguigu.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //定制授权规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        //开启自动配置的登录功能, 如果没有登录 或 没有权限 就会来到登录页面
        http.formLogin().loginPage("/userlogin").usernameParameter("user").passwordParameter("pwd").loginProcessingUrl("/login");
        /**
         * 1./login来到登录首页
         * 2.重定向到/login?error表示登录失败
         * 3.默认post形式的/login代表处理登录
         * 4.一旦定制loginpage，那么 loginpage 的post请求就是登录
         */
        //开启自动配置的注销功能，并清空session，注销成功返回/login?logout页面
        http.logout().logoutSuccessUrl("/");

        //开启记住功能
        http.rememberMe().rememberMeParameter("remeber");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1")
                .and()
                .withUser("lisi").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP2")
                .and()
                .withUser("zhantgsan").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP3");
    }
}
