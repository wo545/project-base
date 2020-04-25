package com.shiyf.security.controller;

import com.shiyf.security.utils.CommonResult;
import com.shiyf.security.utils.JWTUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
public class LoginController {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JWTUtils jwtUtils;

    @GetMapping("/index")
    @ResponseBody
    public String index(){
        return "index";
    }
    @GetMapping("/hello")
    @ResponseBody
    public String hello(){
        return "hello world";
    }

    @PostMapping("/login")
    @ResponseBody
    public CommonResult<Object> login(@RequestBody Map map){
        String username = (String) map.get("username");
        String password = (String) map.get("password")
                ;
        System.out.println("用户登录"+ username + password);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if(!passwordEncoder.matches(password,userDetails.getPassword())){
            throw new BadCredentialsException("用户名或密码不正确");
        }
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtUtils.generateToken(userDetails);
        System.out.println(token);
        return CommonResult.success(token);
    }
    @PostMapping("/checkLogin")
    @ResponseBody
    public CommonResult<Object> checkLogin( String token){
        jwtUtils.validateToken(token);
        return CommonResult.success(token);
    }

}
