package com.mysite.pch.config;

import com.mysite.pch.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {
    /*
    우리가 직접 로그인 처리를 안해도 되는 대신 지정해줘야 할 정보들
    POST /login 에 대한 요청을 security가 가로채서 로그인 진행해주기 때문에 우리가 직접 @PostMapping("/login") 을 만들지 않아도 됨
    로그인에 성공하면 Security Session을 생성해 줌 (Key값 : Security ContextHolder)
    Security Session(Authentication(UserDetails)) 이런 식의 구조로 되어있는데 PrincipalDetails에서 UserDetails를 설정해준다고 보면 됨
     */

    //implements UserDetails 사용할려면 인터페이스 안에 있는 모든 메서드를 사용해야함

    private User user;
    public PrincipalDetails(User user){
        this.user=user;
    }
    //권한 관련 작업을 하기 위한 role return
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        Collection<GrantedAuthority> collections =new ArrayList<>();
        collections.add(()->{
            return user.getRole().name();
        });
        return collections;
    }

    //get Password 메서드
    @Override
    public String getPassword(){
        return user.getPassword();
    }
    // get Username 메서드 (생성한 User은 loginId 사용)
    @Override
    public String getUsername() {
        return user.getLoginId();
    }

    // 계정이 만료되었는지 (true : 만료 x )
    @Override
    public boolean isAccountNonExpired(){
        return true;
    }
    //계정이 잠겼는지 ( true : 잠기지않음)
    @Override
    public boolean isAccountNonLocked(){
        return  true;
    }
    // 비밀번호가 만료되었는지 (true: 만료X)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    // 계정이 활성화(사용가능)인지 (true: 활성화)
    @Override
    public boolean isEnabled() {
        return true;
    }

}
