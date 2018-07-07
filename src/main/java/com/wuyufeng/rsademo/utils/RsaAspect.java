package com.wuyufeng.rsademo.utils;
import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAPrivateKey;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;  
  
@Aspect  
@Component  
public class RsaAspect {  
    @Pointcut("execution(public * com.wuyufeng.rsademo.controller.*.rsa*(..))")
    public void webLog(){}
  
    // 在需要解密的controller之前解密好
    @Around("webLog()")  
    public Object arround(ProceedingJoinPoint pjp) throws UnsupportedEncodingException {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();  
        HttpServletRequest request = attributes.getRequest();  
        HttpSession session = request.getSession();
        
    	Object[] args = pjp.getArgs();
    	args[0] = getRsaDecryptStr(args[0].toString(), session);
        try {
            return pjp.proceed(args);
        } catch (Throwable e) {  
            e.printStackTrace();
            return null;  
        }  
    }
    
	private String getRsaDecryptStr(String data, HttpSession session) throws UnsupportedEncodingException {
		RSAPrivateKey privateKey = (RSAPrivateKey)session.getAttribute("privateKey");
		String decryptPassword = RsaEncryptionUtil.decryptString(privateKey, data);
		decryptPassword = java.net.URLDecoder.decode(StringUtils.reverse(decryptPassword) ,"UTF-8");
		return decryptPassword;
	}
}