package com.wuyufeng.rsademo.controller;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.wuyufeng.rsademo.utils.RsaEncryptionUtil;

@Controller
public class RootController {
	
	@GetMapping("/testRsa")
	public String testRsa(Model model, HttpSession session) {
		setModelRsaEncrypt(model, session);
		return "rsa_test";
	}
	
	
	@PostMapping("/testDecrype")
	@ResponseBody
	public String testDecrype(String data, HttpSession session) throws UnsupportedEncodingException {
		String decryptPassword = getRsaDecryptStr(data, session);
		System.out.println("解密后的数据为："+ decryptPassword);
		return decryptPassword;
	}

	private void setModelRsaEncrypt(Model model, HttpSession session) {
		KeyPair keyPair = RsaEncryptionUtil.getKeyPair();
		RSAPublicKey public1 = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey private1 = (RSAPrivateKey)keyPair.getPrivate();
		String publicExponent =  new BigInteger(public1.getPublicExponent().toString(), 10).toString(16);
		String modulus = new BigInteger(public1.getModulus().toString(), 10).toString(16);
		
		session.setAttribute("privateKey", private1);
		model.addAttribute("publicExponent", publicExponent);
		model.addAttribute("publicModulus", modulus);
	}

	private String getRsaDecryptStr(String data, HttpSession session) throws UnsupportedEncodingException {
		RSAPrivateKey privateKey = (RSAPrivateKey)session.getAttribute("privateKey");
		String decryptPassword = RsaEncryptionUtil.decryptString(privateKey, data);
		decryptPassword = java.net.URLDecoder.decode(StringUtils.reverse(decryptPassword) ,"UTF-8");
		return decryptPassword;
	}
}
