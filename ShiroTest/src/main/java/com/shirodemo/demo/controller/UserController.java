package com.shirodemo.demo.controller;

import com.shirodemo.demo.vo.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class UserController {
    @PostMapping("/login")
    public String login(User user){
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(),user.getPassword());
        try{
            subject.login(token);
            return "登陆成功";
        }catch (AuthenticationException e){
            return e.getMessage();
        }
    }

    @RequiresRoles("user")
    @GetMapping("/testRoles")
    public String testRoles(){
        return  "testRole success";
    }

    @RequiresPermissions({"user:add"})
    @GetMapping("/testPermissions")
    public String testPermissions(){
        return  "testPermissions success";
    }

    @GetMapping("/testRoles1")
    public String testRoles1(){
        return  "testRole success";
    }


}
