package com.shirodemo.demo.dao;

import com.shirodemo.demo.vo.User;

import java.util.List;

public interface UserDAO {
    User findUserByUsername(String username);

    List<String> findRolesByUsername(String username);
}
