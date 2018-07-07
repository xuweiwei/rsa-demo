//package com.wuyufeng.rsademo.utils;
//
//import java.io.IOException;
//import java.io.PrintWriter;
//import java.math.BigInteger;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.util.HashMap;
//import java.util.Map;
// 
//import javax.servlet.ServletException;
//import javax.servlet.annotation.WebServlet;
//import javax.servlet.http.HttpServlet;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
// 
// 
//@WebServlet("/rsaser")
//public class RsaServlet extends HttpServlet {
// 
//	/**
//	 * 
//	 */
//	private static final long serialVersionUID = 1L;
//
//	public RsaServlet() {
//		super();
//	}
// 
//	public void destroy() {
//		super.destroy();
//	}
// 
//	public void doGet(HttpServletRequest request, HttpServletResponse response)
//			throws ServletException, IOException {
//		request.setCharacterEncoding("utf-8");
//		response.setCharacterEncoding("utf-8");
//		
//		String worktype = request.getParameter("worktype");
//		
//		if(worktype!=null){
//			
//			//获取加密所需的参数信息
//			if(worktype.equals("turn")){
//				
//				RSAPublicKey publicKey = RSAUtil.getDefaultPublicKey();
//				RSAPrivateKey privateKey = RSAUtil.getDefaultPrivateKey();
//				Rsaobj rsaobj =  new Rsaobj(publicKey, privateKey);
//				
//				
//				String publicExponent_16 =  new BigInteger(publicKey.getPublicExponent().toString(), 10).toString(16);
//				String modulus_16 = new BigInteger(publicKey.getModulus().toString(), 10).toString(16);
//				
//				System.out.println("公钥 16 getModulus:"+modulus_16);
//				System.out.println("公钥 16 getPublicExponent:"+publicExponent_16);
//				
//				
//				System.out.println("私钥  getModulus  ："+privateKey.getModulus());
//				System.out.println("私钥  getPrivateExponent   ："+privateKey.getPrivateExponent());
//				
//				
//				//将私钥的 Exponent  Modulus存放至变量中，以便后来构造私钥
//				//MyUtil.PrivateExponent = privateKey.getPrivateExponent();
//				//MyUtil.PrivateModulus = privateKey.getModulus();
//				
//				
//				request.getSession().setAttribute("modulus_16",modulus_16);
//				request.getSession().setAttribute("publicExponent_16",publicExponent_16);
//				request.getSession().setAttribute("rsaobj",rsaobj);
//				
//				
//				request.getRequestDispatcher("./demo.jsp").forward(request, response);
//				
//			
//			//提交加密后的内容 进行解密
//			}else if(worktype.equals("decrypt")){
//				System.out.println("----------decrypt------------");
//				String encrypt_password = request.getParameter("password");
//				String unencrypt_password = request.getParameter("unpassword");
//				System.out.println("未经过加密的数据为:unencrypt_password:"+unencrypt_password);
//				System.out.println("前台加密后的数据为:encrypt_password:"+encrypt_password);
//				
//				Object object = request.getSession().getAttribute("rsaobj");
//				
//				if(object!=null){
//					Rsaobj rsaobj = (Rsaobj) object;
//					
//					//从 session 中获取私钥
//					RSAPrivateKey privateKey = rsaobj.getPrivateKey();
//					
//					//从变量中获取数据 构造私钥
//					/*RSAPrivateKey privateKey = new RSAPrivateKey() {
//						
//						@Override
//						public BigInteger getModulus() {
//							return MyUtil.PrivateModulus;
//						}
//						
//						@Override
//						public String getFormat() {
//							return null;
//						}
//						
//						@Override
//						public byte[] getEncoded() {
//							return null;
//						}
//						
//						@Override
//						public String getAlgorithm() {
//							return null;
//						}
//						
//						@Override
//						public BigInteger getPrivateExponent() {
//							return MyUtil.PrivateExponent;
//						}
//					};*/
//					
//					
//					
//					
//					
//					String decrypt_password = RSAUtil.decryptString(privateKey, encrypt_password);
//					
//					//对字符串进行URL解码的编码处理
//					decrypt_password = java.net.URLDecoder.decode(new String(decrypt_password) ,"UTF-8");
//					
//					System.out.println("解密后的数据为："+ decrypt_password);
//					
//					
//					Map<String, Object> map = new HashMap<String, Object>();
//					map.put("success", true);
//					map.put("content", new String(decrypt_password));
//					MyUtil.writeToJson(map, response);
//					
//				}
//				
//			}
//			
//		}
//		
//	}
// 
//	public void doPost(HttpServletRequest request, HttpServletResponse response)
//			throws ServletException, IOException {
//		doGet(request, response);
//	}
// 
//	public void init() throws ServletException {
//		
//	}
// 
//}