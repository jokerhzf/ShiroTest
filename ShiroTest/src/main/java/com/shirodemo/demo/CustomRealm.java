package com.shirodemo.demo;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CustomRealm extends AuthorizingRealm {

    public static void main(String[] args){
        //加salt密码
        Md5Hash md5Hash = new Md5Hash("123456","hzf");
        System.out.println(md5Hash);
    }

    //模拟用户数据库数据
    Map<String,String> userMap = new HashMap<>(16);
    {
        userMap.put("admin","eb6bc78c13959df7010c4252584f6ad1");
        super.setName("CostomRealm");
    }

    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String)principalCollection.getPrimaryPrincipal();

        //从数据库根据用户名获取角色数据
        Set<String> roles = getRolesByUsername(username);
        //从数据库根据用户名获取权限数据
        Set<String> permission = getPermissionByUsername(username);

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setStringPermissions(permission);
        simpleAuthorizationInfo.setRoles(roles);
        return simpleAuthorizationInfo;

    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //1.从主体传过来的认证信息中，获取用户名
        String username = (String)authenticationToken.getPrincipal();

        //2.通过用户名去数据库中获取凭证
        String password = getPasswordByUsername(username);
        if(password == null){
            return null;
        }

        //设置加密
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username,password,"costomRealm");
        authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("hzf"));

        return authenticationInfo;

    }

    /**
     * 模拟用户权限信息
     * @param username
     * @return
     */
    private Set<String> getPermissionByUsername(String username){
        Set<String> sets = new HashSet<String>();
        sets.add("user:delete");
        sets.add("user:add");
        return sets;
    }

    /**
     * 根据用户名获取数据库中的角色数据
     * @param username
     * @return
     */
    private Set<String> getRolesByUsername(String username){
        Set<String> sets = new HashSet<String>();
        sets.add("admin");
        sets.add("user");
        return sets;
    }

    /**
     * 从用户数据中查询密码
     * @param username
     * @return
     */
    private String getPasswordByUsername(String username){
        Set<String> sets = new HashSet<String>();
        return userMap.get(username);
    }
}
