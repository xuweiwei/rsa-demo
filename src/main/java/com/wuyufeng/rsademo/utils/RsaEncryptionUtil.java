package com.wuyufeng.rsademo.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * RSA 加解密 工具类
 * 
 * @author yangnuo 创建时间：2017年7月3日
 */
public class RsaEncryptionUtil {

	/** 算法名称 */
	private static final String ALGORITHOM = "RSA";

	/** 密钥大小 */
	private static final int KEY_SIZE = 1024;

	/** 默认的安全服务提供者 */
	private static final Provider DEFAULT_PROVIDER = new BouncyCastleProvider();

	private static KeyPairGenerator keyPairGen = null;

	private static KeyFactory keyFactory = null;

	static {
		try {
			keyPairGen = KeyPairGenerator.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
			keyFactory = KeyFactory.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
		} catch (NoSuchAlgorithmException ex) {
		}
	}

	private RsaEncryptionUtil() {

	}

	/**
	 * 生成并返回RSA密钥对。
	 */
	private static synchronized KeyPair generateKeyPair() {
		try {
			keyPairGen.initialize(KEY_SIZE, new SecureRandom());
			return keyPairGen.generateKeyPair();
		} catch (InvalidParameterException ex) {
		} catch (NullPointerException ex) {
		}
		return null;
	}

	/**
	 * 返回RSA密钥对。
	 */
	public static KeyPair getKeyPair() {
		return generateKeyPair();
	}

	/***********************************************************************
	 * 加 密
	 *******************************************************************************************/

	/**
	 * 使用指定的公钥加密数据。
	 * 
	 * @param publicKey
	 *            给定的公钥。
	 * @param data
	 *            要加密的数据。
	 * @return 加密后的数据。
	 */
	public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {
		Cipher ci = Cipher.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
		ci.init(Cipher.ENCRYPT_MODE, publicKey);
		return ci.doFinal(data);
	}

	/**
	 * 使用给定的公钥加密给定的字符串。 若 {@code publicKey} 为 {@code null}，或者 {@code plaintext} 为
	 * {@code null} 则返回 {@code
	 * null}。
	 * 
	 * @param publicKey
	 *            给定的公钥。
	 * @param plaintext
	 *            字符串。
	 * @return 给定字符串的密文。
	 */
	public static String encryptString(PublicKey publicKey, String plaintext) {
		if (publicKey == null || plaintext == null) {
			return null;
		}
		byte[] data = plaintext.getBytes();
		try {
			byte[] en_data = encrypt(publicKey, data);
			return new String(Hex.encodeHex(en_data));
		} catch (Exception ex) {
		}
		return null;
	}

	/***********************************************************************
	 * 解 密
	 *******************************************************************************************/

	/**
	 * 使用指定的私钥解密数据。
	 * 
	 * @param privateKey
	 *            给定的私钥。
	 * @param data
	 *            要解密的数据。
	 * @return 原数据。
	 */
	public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception {
		Cipher ci = Cipher.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
		ci.init(Cipher.DECRYPT_MODE, privateKey);
		return ci.doFinal(data);
	}

	/**
	 * 使用给定的私钥解密给定的字符串。 若私钥为 {@code null}，或者 {@code encrypttext} 为
	 * {@code null}或空字符串则返回 {@code null}。 私钥不匹配时，返回 {@code null}。
	 * 
	 * @param privateKey
	 *            给定的私钥。
	 * @param encrypttext
	 *            密文。
	 * @return 原文字符串。
	 */
	public static String decryptString(PrivateKey privateKey, String encrypttext) {
		if (privateKey == null || StringUtils.isBlank(encrypttext)) {
			return null;
		}
		try {
			byte[] en_data = Hex.decodeHex(encrypttext.toCharArray());
			byte[] data = decrypt(privateKey, en_data);
			return new String(data);
		} catch (Exception ex) {
		}
		return null;
	}

	/**
	 * 通过密钥 解密经过js加密的内容
	 * 
	 * @param privateKey
	 * @param encrypttext
	 * @return
	 */
	public static String decryptStringByJs(RSAPrivateKey privateKey, String encrypttext) {
		String text = decryptString(privateKey, encrypttext);
		if (text == null) {
			return null;
		}
		return StringUtils.reverse(text);
	}

	/*******************************************************************
	 * 构造 RSA
	 ***********************************************************************************************/

	/**
	 * 根据给定的系数和专用指数构造一个RSA专用的公钥对象。
	 * 
	 * @param modulus
	 *            系数。
	 * @param publicExponent
	 *            专用指数。
	 * @return RSA专用公钥对象。
	 */
	public static RSAPublicKey generateRSAPublicKey(byte[] modulus, byte[] publicExponent) {
		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
		try {
			return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException ex) {
		} catch (NullPointerException ex) {
		}
		return null;
	}

	/**
	 * 根据给定的系数和专用指数构造一个RSA专用的私钥对象。
	 * 
	 * @param modulus
	 *            系数。
	 * @param privateExponent
	 *            专用指数。
	 * @return RSA专用私钥对象。
	 */
	public static RSAPrivateKey generateRSAPrivateKey(byte[] modulus, byte[] privateExponent) {
		RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus),
				new BigInteger(privateExponent));
		try {
			return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		} catch (InvalidKeySpecException ex) {
		} catch (NullPointerException ex) {
		}
		return null;
	}

	/**
	 * 根据给定的16进制系数和专用指数字符串构造一个RSA专用的私钥对象。
	 * 
	 * @param modulus
	 *            系数。
	 * @param privateExponent
	 *            专用指数。
	 * @return RSA专用私钥对象。
	 */
	public static RSAPrivateKey getRSAPrivateKey(String hexModulus, String hexPrivateExponent) {
		if (StringUtils.isBlank(hexModulus) || StringUtils.isBlank(hexPrivateExponent)) {
			return null;
		}
		byte[] modulus = null;
		byte[] privateExponent = null;
		try {
			modulus = Hex.decodeHex(hexModulus.toCharArray());
			privateExponent = Hex.decodeHex(hexPrivateExponent.toCharArray());
		} catch (DecoderException ex) {
		}
		if (modulus != null && privateExponent != null) {
			return generateRSAPrivateKey(modulus, privateExponent);
		}
		return null;
	}

	/**
	 * 根据给定的16进制系数和专用指数字符串构造一个RSA专用的公钥对象。
	 * 
	 * @param modulus
	 *            系数。
	 * @param publicExponent
	 *            专用指数。
	 * @return RSA专用公钥对象。
	 */
	public static RSAPublicKey getRSAPublidKey(String hexModulus, String hexPublicExponent) {
		if (StringUtils.isBlank(hexModulus) || StringUtils.isBlank(hexPublicExponent)) {
			return null;
		}
		byte[] modulus = null;
		byte[] publicExponent = null;
		try {
			modulus = Hex.decodeHex(hexModulus.toCharArray());
			publicExponent = Hex.decodeHex(hexPublicExponent.toCharArray());
		} catch (DecoderException ex) {
		}
		if (modulus != null && publicExponent != null) {
			return generateRSAPublicKey(modulus, publicExponent);
		}
		return null;
	}

	/***********************************************************************
	 * 测 试
	 *******************************************************************************************/

	public static void main(String[] args) throws DecoderException {
		// 首先生成秘钥对
/*		KeyPair keyPair = generateKeyPair();

		RSAPublicKey rsapublicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey rsaprivateKey = (RSAPrivateKey) keyPair.getPrivate();

		// 获取密钥对中的模数和指数
		final KeyTwin keyTwin = new KeyTwin(rsapublicKey.getModulus().toString(),
				rsapublicKey.getPublicExponent().toString(), rsaprivateKey.getModulus().toString(),
				rsaprivateKey.getPrivateExponent().toString());
		System.out.println(keyTwin.toString());

		String data = "落花雨abc123456";

		// 构造 公钥
		RSAPublicKey publicKey = new RSAPublicKey() {
			private static final long serialVersionUID = 1L;

			@Override
			public BigInteger getModulus() {
				return new BigInteger(keyTwin.getPulicModulus());
			}

			@Override
			public String getFormat() {
				return null;
			}

			@Override
			public byte[] getEncoded() {
				return null;
			}

			@Override
			public String getAlgorithm() {
				return null;
			}

			@Override
			public BigInteger getPublicExponent() {
				return new BigInteger(keyTwin.getPulicExponent());
			}
		};
		// 使用构造的公钥对前台的数据进行加密
		String encryptString = encryptString(publicKey, data);

		System.out.println("加密后的字符串为：" + encryptString);

		// 构造私钥
		RSAPrivateKey privateKey = new RSAPrivateKey() {
			private static final long serialVersionUID = 1L;

			@Override
			public BigInteger getModulus() {
				return new BigInteger(keyTwin.getPrivatemodulus());
			}

			@Override
			public String getFormat() {
				return null;
			}

			@Override
			public byte[] getEncoded() {
				return null;
			}

			@Override
			public String getAlgorithm() {
				return null;
			}

			@Override
			public BigInteger getPrivateExponent() {
				return new BigInteger(keyTwin.getPrivateexponent());
			}
		};

		String decryptString = decryptString(privateKey, encryptString);
		System.out.println("解密后的字符串为：" + decryptString);*/
		
		
		// --------------------------------------
		KeyPair keyPair2 = generateKeyPair();
		RSAPublicKey publicKey2 = (RSAPublicKey) keyPair2.getPublic();
		RSAPrivateKey privateKey2 = (RSAPrivateKey) keyPair2.getPrivate();

		System.out.println("publicKey-->" + publicKey2);
		System.out.println("privateKey-->" + privateKey2);

		String data1 = "123456";
		// 加密
		String codeString = encryptString(publicKey2, data1);
		System.out.println(codeString);
		// 解密
		System.out.println(decryptString(privateKey2, codeString));

	}

}
