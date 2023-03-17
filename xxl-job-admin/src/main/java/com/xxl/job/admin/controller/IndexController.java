package com.xxl.job.admin.controller;

import com.para.secure.client.model.UserInfo;
import com.para.secure.exceptions.OAuthApiException;
import com.para.secure.model.Token;
import com.para.secure.oauth.OAuthService;
import com.xxl.job.admin.config.SsoConfig;
import com.xxl.job.admin.controller.annotation.PermissionLimit;
import com.xxl.job.admin.core.model.XxlJobUser;
import com.xxl.job.admin.dao.XxlJobUserDao;
import com.xxl.job.admin.service.LoginService;
import com.xxl.job.admin.service.XxlJobService;
import com.xxl.job.core.biz.model.ReturnT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * index controller
 *
 * @author xuxueli 2015-12-19 16:13:16
 */
@Controller
public class IndexController {

    private static Logger logger = LoggerFactory.getLogger(IndexController.class);

    @Resource
    private XxlJobService xxlJobService;
    @Resource
    private LoginService loginService;

    @Resource
    private SsoConfig ssoConfig;

    @Resource
    private XxlJobUserDao xxlJobUserDao;

    @RequestMapping("/")
    public String index(Model model) {

        Map<String, Object> dashboardMap = xxlJobService.dashboardInfo();
        model.addAllAttributes(dashboardMap);

        return "index";
    }

    @RequestMapping("/chartInfo")
    @ResponseBody
    public ReturnT<Map<String, Object>> chartInfo(Date startDate, Date endDate) {
        ReturnT<Map<String, Object>> chartInfo = xxlJobService.chartInfo(startDate, endDate);
        return chartInfo;
    }

    @RequestMapping("/toLogin")
    @PermissionLimit(limit = false)
    public ModelAndView toLogin(HttpServletRequest request, HttpServletResponse response, ModelAndView modelAndView) {
        if (loginService.ifLogin(request, response) != null) {
            modelAndView.setView(new RedirectView("/", true, false));
            return modelAndView;
        }
        return new ModelAndView("login");
    }

    @RequestMapping(value = "login", method = RequestMethod.POST)
    @ResponseBody
    @PermissionLimit(limit = false)
    public ReturnT<String> loginDo(HttpServletRequest request, HttpServletResponse response, String userName, String password, String ifRemember) {
        boolean ifRem = (ifRemember != null && ifRemember.trim().length() > 0 && "on".equals(ifRemember)) ? true : false;
        return loginService.login(request, response, userName, password, ifRem);
    }

    @RequestMapping(value = "logout", method = RequestMethod.POST)
    @ResponseBody
    @PermissionLimit(limit = false)
    public ReturnT<String> logout(HttpServletRequest request, HttpServletResponse response) {
        return loginService.logout(request, response);
    }

    @RequestMapping("/help")
    public String help() {

		/*if (!PermissionInterceptor.ifLogin(request)) {
			return "redirect:/toLogin";
		}*/

        return "help";
    }

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        dateFormat.setLenient(false);
        binder.registerCustomEditor(Date.class, new CustomDateEditor(dateFormat, true));
    }

    @RequestMapping("/toCeibsSso")
    @PermissionLimit(limit = false)
    public String toCeibsSso() {
        OAuthService oAuthService = new OAuthService(ssoConfig.getClientId(), ssoConfig.getClientSecret(), ssoConfig.getCallbackUrl());
        return "redirect:" + oAuthService.getAuthorizationUrl();
    }

    @RequestMapping("/ceibs/ssoCallback")
    @PermissionLimit(limit = false)
    public String ceibsSsoCallback(@RequestParam String code, HttpServletResponse response) throws OAuthApiException {
        OAuthService oAuthService = new OAuthService(ssoConfig.getClientId(), ssoConfig.getClientSecret(), ssoConfig.getCallbackUrl());
        Token token = oAuthService.getAccessToken(code);
        UserInfo userInfo = new UserInfo(token);
        UserInfo ceibsUserInfo = userInfo.getCeibsUserInfo();
        checkUserTeam(ceibsUserInfo);
        String userId = ceibsUserInfo.getId();
        XxlJobUser user = xxlJobUserDao.loadByUserName(userId);
        if (user == null) {
            // 初始化用户
            user = initUserWithCeibsUserInfo(userId);
        }
        loginService.loginWithUserName(response, user);
        // 存在用户 跳转到首页
        return "redirect:/";
    }

    private void checkUserTeam(UserInfo ceibsUserInfo) {
        if (!"is".equalsIgnoreCase(ceibsUserInfo.getClassOrTeam())) {
            throw new RuntimeException("暂无权限登录此系统");
        }
    }

    private XxlJobUser initUserWithCeibsUserInfo(String userId) {
        XxlJobUser user = new XxlJobUser();
        user.setUsername(userId);
        String password = UUID.randomUUID().toString();
        user.setPassword(DigestUtils.md5DigestAsHex(password.getBytes()));
        user.setRole(1);
        xxlJobUserDao.save(user);
        return user;
    }
}
