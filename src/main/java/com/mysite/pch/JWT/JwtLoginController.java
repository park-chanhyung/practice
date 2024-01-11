package com.mysite.pch.JWT;

import com.mysite.pch.DTO.JoinRequest;
import com.mysite.pch.DTO.LoginRequest;
import com.mysite.pch.user.User;
import com.mysite.pch.user.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;




@Controller
@RequiredArgsConstructor
@RequestMapping("/jwt-login")
public class JwtLoginController {

    private final UserService userService;

    @GetMapping(value = {"", "/"})
    public String home(Model model, Authentication auth) {
      // 로그인 타입 , 페이지명 추가
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        // 인증정보가 있으면 닉네임을 모델에 추가
        if(auth != null) {
            User loginUser = userService.getLoginUserByLoginId(auth.getName());
            if (loginUser != null) {
                model.addAttribute("nickname", loginUser.getNickname());
            }
        }

        return "home";
    }
    //회원가입 페이지
    @GetMapping("/join")
    public String joinPage(Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        model.addAttribute("joinRequest", new JoinRequest());
        return "join";
    }
//회원가입 처리
    @PostMapping("/join")
    public String join(@Valid @ModelAttribute JoinRequest joinRequest, BindingResult bindingResult, Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        // loginId 중복 체크
        if(userService.checkLoginIdDuplicate(joinRequest.getLoginId())) {
            bindingResult.addError(new FieldError("joinRequest", "loginId", "로그인 아이디가 중복됩니다."));
        }
        // 닉네임 중복 체크
        if(userService.checkNicknameDuplicate(joinRequest.getNickname())) {
            bindingResult.addError(new FieldError("joinRequest", "nickname", "닉네임이 중복됩니다."));
        }
        // password와 passwordCheck가 같은지 체크
        if(!joinRequest.getPassword().equals(joinRequest.getPasswordCheck())) {
            bindingResult.addError(new FieldError("joinRequest", "passwordCheck", "바밀번호가 일치하지 않습니다."));
        }
        // 에러가 있으면 회원가입 페이지로 돌아감
        if(bindingResult.hasErrors()) {
            return "join";
        }
    // 회원가입 성공하면 홈페이지로
        userService.join2(joinRequest);
        return "redirect:/jwt-login";
    }

    //로그인페이지
    @GetMapping("/login")
    public String loginPage(Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        model.addAttribute("loginRequest", new LoginRequest());
        return "login";
    }
    // 로그인 처리
    @PostMapping("/login")
    public String login(@ModelAttribute LoginRequest loginRequest, BindingResult bindingResult,
                        HttpServletResponse response, Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        User user = userService.login(loginRequest);

        // 로그인 아이디나 비밀번호가 틀린 경우 global error return
        if(user == null) {
            bindingResult.reject("loginFail", "로그인 아이디 또는 비밀번호가 틀렸습니다.");
        }

        if(bindingResult.hasErrors()) {
            return "login";
        }

        // 로그인 성공 => Jwt Token 발급
        String secretKey = "my-secret-key-123123";
        long expireTimeMs = 1000 * 60 * 10;     // Token 유효 시간 = 10분

        String jwtToken = JwtTokenUtil.createToken(user.getLoginId(), secretKey, expireTimeMs);

        // 발급한 Jwt Token을 Cookie를 통해 전송
        // 클라이언트는 다음 요청부터 Jwt Token이 담긴 쿠키 전송 => 이 값을 통해 인증, 인가 진행
        Cookie cookie = new Cookie("jwtToken", jwtToken);
        cookie.setMaxAge(60 * 10);  // 쿠키 유효 시간 : 10분
        response.addCookie(cookie);

        return "redirect:/jwt-login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response, Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        // 쿠키 파기
        Cookie cookie = new Cookie("jwtToken", null);
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return "redirect:/jwt-login";
    }
    // 내정보
    @GetMapping("/info")
    public String userInfo(Model model, Authentication auth) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        User loginUser = userService.getLoginUserByLoginId(auth.getName());
        model.addAttribute("user", loginUser);

        return "info";
    }

    @GetMapping("/admin")
    public String adminPage(Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        return "admin";
    }
// 인증실패 페이지
    @GetMapping("/authentication-fail")
    public String authenticationFail(Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        return "errorPage/authenticationFail";
    }
// 인가실패 페이지
    @GetMapping("/authorization-fail")
    public String authorizationFail(Model model) {
        model.addAttribute("loginType", "jwt-login");
        model.addAttribute("pageName", "Jwt Token 화면 로그인");

        return "errorPage/authorizationFail";
    }
}
