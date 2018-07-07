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
 * RSA 加解密  工具类
 * @author yangnuo
 * 创建时间：2017年7月3日
 */
public class RSAUtil {
 
        /** 算法名称 */
        private static final String ALGORITHOM = "RSA";
         
        /**保存生成的密钥对的文件名称。 */
        private static final String RSA_PAIR_FILENAME = "/_RSA_ENCRYPTION.txt";
         
        /** 密钥大小 */
        private static final int KEY_SIZE = 1024;
         
        /** 默认的安全服务提供者 */
        private static final Provider DEFAULT_PROVIDER = new BouncyCastleProvider();
 
        private static KeyPairGenerator keyPairGen = null;
         
        private static KeyFactory keyFactory = null;
         
        /** 缓存的密钥对。 */
        private static KeyPair oneKeyPair = null;
 
        private static File rsaPairFile = null;
 
        static {
            try {
                keyPairGen = KeyPairGenerator.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
                keyFactory = KeyFactory.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
            } catch (NoSuchAlgorithmException ex) {
            }
            rsaPairFile = new File(getRSAPairFilePath());
            System.out.println(rsaPairFile.getAbsolutePath());
        }
 
        private RSAUtil() { }
 
        /**
         * 生成并返回RSA密钥对。
         */
        private static synchronized KeyPair generateKeyPair() {
            try {
                keyPairGen.initialize(KEY_SIZE, new SecureRandom());
                oneKeyPair = keyPairGen.generateKeyPair();
                saveKeyPair(oneKeyPair);
                return oneKeyPair;
            } catch (InvalidParameterException ex) {
            } catch (NullPointerException ex) {
            }
            return null;
        }
 
        /**
         * 返回生成/读取的密钥对文件的路径。
         */
        private static String getRSAPairFilePath() {
            String urlPath = RSAUtil.class.getResource("/").getPath();
            return (new File(urlPath).getParent() + RSA_PAIR_FILENAME);
        }
 
        /**
         * 若需要创建新的密钥对文件，则返回 {@code true}，否则 {@code false}。
         */
        private static boolean isCreateKeyPairFile() {
            // 是否创建新的密钥对文件
            boolean createNewKeyPair = false;
            if (!rsaPairFile.exists() || rsaPairFile.isDirectory()) {
                createNewKeyPair = true;
            }
            return createNewKeyPair;
        }
 
        /**
         * 将指定的RSA密钥对以文件形式保存。
         * 
         * @param keyPair 要保存的密钥对。
         */
        private static void saveKeyPair(KeyPair keyPair) {
            FileOutputStream fos = null;
            ObjectOutputStream oos = null;
            try {
                fos = FileUtils.openOutputStream(rsaPairFile);
                oos = new ObjectOutputStream(fos);
                oos.writeObject(keyPair);
            } catch (Exception ex) {
                ex.printStackTrace();
            } finally {
                IOUtils.closeQuietly(oos);
                IOUtils.closeQuietly(fos);
            }
        }
 
        /**
         * 返回RSA密钥对。
         */
        public static KeyPair getKeyPair() {
            // 首先判断是否需要重新生成新的密钥对文件
            if (isCreateKeyPairFile()) {
                // 直接强制生成密钥对文件，并存入缓存。
                return generateKeyPair();
            }
            if (oneKeyPair != null) {
                return oneKeyPair;
            }
            return readKeyPair();
        }
         
        // 同步读出保存的密钥对
        private static KeyPair readKeyPair() {
            FileInputStream fis = null;
            ObjectInputStream ois = null;
            try {
                fis = FileUtils.openInputStream(rsaPairFile);
                ois = new ObjectInputStream(fis);
                oneKeyPair = (KeyPair) ois.readObject();
                return oneKeyPair;
            } catch (Exception ex) {
                ex.printStackTrace();
            } finally {
                IOUtils.closeQuietly(ois);
                IOUtils.closeQuietly(fis);
            }
            return null;
        }
 
        /**
         * 根据给定的系数和专用指数构造一个RSA专用的公钥对象。
         * 
         * @param modulus 系数。
         * @param publicExponent 专用指数。
         * @return RSA专用公钥对象。
         */
        public static RSAPublicKey generateRSAPublicKey(byte[] modulus, byte[] publicExponent) {
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(modulus),
                    new BigInteger(publicExponent));
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
         * @param modulus 系数。
         * @param privateExponent 专用指数。
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
         * @param modulus 系数。
         * @param privateExponent 专用指数。
         * @return RSA专用私钥对象。
         */
        public static RSAPrivateKey getRSAPrivateKey(String hexModulus, String hexPrivateExponent) {
            if(StringUtils.isBlank(hexModulus) || StringUtils.isBlank(hexPrivateExponent)) {
                return null;
            }
            byte[] modulus = null;
            byte[] privateExponent = null;
            try {
                modulus = Hex.decodeHex(hexModulus.toCharArray());
                privateExponent = Hex.decodeHex(hexPrivateExponent.toCharArray());
            } catch(DecoderException ex) {
            }
            if(modulus != null && privateExponent != null) {
                return generateRSAPrivateKey(modulus, privateExponent);
            }
            return null;
        }
         
        /**
         * 根据给定的16进制系数和专用指数字符串构造一个RSA专用的公钥对象。
         * 
         * @param modulus 系数。
         * @param publicExponent 专用指数。
         * @return RSA专用公钥对象。
         */
        public static RSAPublicKey getRSAPublidKey(String hexModulus, String hexPublicExponent) {
            if(StringUtils.isBlank(hexModulus) || StringUtils.isBlank(hexPublicExponent)) {
                return null;
            }
            byte[] modulus = null;
            byte[] publicExponent = null;
            try {
                modulus = Hex.decodeHex(hexModulus.toCharArray());
                publicExponent = Hex.decodeHex(hexPublicExponent.toCharArray());
            } catch(DecoderException ex) {
            }
            if(modulus != null && publicExponent != null) {
                return generateRSAPublicKey(modulus, publicExponent);
            }
            return null;
        }
 
        /**
         * 使用指定的公钥加密数据。
         * 
         * @param publicKey 给定的公钥。
         * @param data 要加密的数据。
         * @return 加密后的数据。
         */
        public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {
            Cipher ci = Cipher.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
            ci.init(Cipher.ENCRYPT_MODE, publicKey);
            return ci.doFinal(data);
        }
 
        /**
         * 使用指定的私钥解密数据。
         * 
         * @param privateKey 给定的私钥。
         * @param data 要解密的数据。
         * @return 原数据。
         */
        public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception {
            Cipher ci = Cipher.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
            ci.init(Cipher.DECRYPT_MODE, privateKey);
            return ci.doFinal(data);
        }
 
        /**
         * 使用给定的公钥加密给定的字符串。
         * 若 {@code publicKey} 为 {@code null}，或者 {@code plaintext} 为 {@code null} 则返回 {@code
         * null}。
         * 
         * @param publicKey 给定的公钥。
         * @param plaintext 字符串。
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
         
        /**
         * 使用默认的公钥加密给定的字符串。
         * 若{@code plaintext} 为 {@code null} 则返回 {@code null}。
         * 
         * @param plaintext 字符串。
         * @return 给定字符串的密文。
         */
        public static String encryptString(String plaintext) {
            if(plaintext == null) {
                return null;
            }
            byte[] data = plaintext.getBytes();
            KeyPair keyPair = getKeyPair();
            try {
                byte[] en_data = encrypt((RSAPublicKey)keyPair.getPublic(), data);
                return new String(Hex.encodeHex(en_data));
            } catch(NullPointerException ex) {
            } catch(Exception ex) {
            }
            return null;
        }
 
        /**
         * 使用给定的私钥解密给定的字符串。
         * 若私钥为 {@code null}，或者 {@code encrypttext} 为 {@code null}或空字符串则返回 {@code null}。
         * 私钥不匹配时，返回 {@code null}。
         * 
         * @param privateKey 给定的私钥。
         * @param encrypttext 密文。
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
         * 使用默认的私钥解密给定的字符串。
         * 若{@code encrypttext} 为 {@code null}或空字符串则返回 {@code null}。
         * 私钥不匹配时，返回 {@code null}。
         * 
         * @param encrypttext 密文。
         * @return 原文字符串。
         */
        public static String decryptString(String encrypttext) {
            if(StringUtils.isBlank(encrypttext)) {
                return null;
            }
            KeyPair keyPair = getKeyPair();
            try {
                byte[] en_data = Hex.decodeHex(encrypttext.toCharArray());
                byte[] data = decrypt((RSAPrivateKey)keyPair.getPrivate(), en_data);
                return new String(data);
            } catch(NullPointerException ex) {
            } catch (Exception ex) {
            }
            return null;
        }
         
        /**
         * 使用默认的私钥解密由JS加密（使用此类提供的公钥加密）的字符串。
         * 
         * @param encrypttext 密文。
         * @return {@code encrypttext} 的原文字符串。
         */
        public static String decryptStringByJs(String encrypttext) {
            String text = decryptString(encrypttext);
            if(text == null) {
                return null;
            }
            return StringUtils.reverse(text);
        }
        /**
         * 与文中参考的博客不同，添加了该方法
         * @param privateKey
         * @param encrypttext
         * @return
         */
        public static String decryptStringByJs(RSAPrivateKey privateKey, String encrypttext) {
            String text = decryptString(privateKey, encrypttext);
            if(text == null) {
                return null;
            }
            return StringUtils.reverse(text);
        }
         
         
        /** 返回已初始化的默认的公钥。*/
        public static RSAPublicKey getDefaultPublicKey() {
            KeyPair keyPair = getKeyPair();
            if(keyPair != null) {
                return (RSAPublicKey)keyPair.getPublic();
            }
            return null;
        }
         
        /** 返回已初始化的默认的私钥。*/
        public static RSAPrivateKey getDefaultPrivateKey() {
            KeyPair keyPair = getKeyPair();
            if(keyPair != null) {
                return (RSAPrivateKey)keyPair.getPrivate();
            }
            return null;
        }
        
        
        public static void main(String[] args) throws DecoderException {
            RSAPublicKey publicKey = getDefaultPublicKey();
            RSAPrivateKey privateKey = getDefaultPrivateKey();
            
            System.out.println("publicKey-->"+publicKey);
            System.out.println("privateKey-->"+privateKey);
             
            String data = "123456";
            //加密
            String codeString = encryptString(publicKey, data);
            System.out.println(codeString);
            //解密
            System.out.println(decryptString(privateKey, codeString));
       }
}
