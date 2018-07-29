package com.sk.RSA;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * RSA安全编码组件 1、生成公私钥对; Map<String, Object> keyMap = RSAUtil.initKey(); String
 * publickey = RSAUtil.getPublicKey(keyMap); String privatekey =
 * RSAUtil.getPrivateKey(keyMap); 2、使用公钥加密，私钥解密 encryptByPublicKey(byte[] data,
 * String key) decryptByPrivateKey(byte[] data, String key) 3、使用私钥加密，公钥解密
 * encryptByPrivateKey(byte[] data, String key) decryptByPublicKey(byte[] data,
 * String key) 4、使用私钥签名，公钥验签 sign(byte[] data, String privateKey) verify(byte[]
 * data, String publicKey, String sign)
 */
public abstract class RSAUtil {
	public static final String KEY_ALGORITHM = "RSA";
	public static final String SIGNATURE_ALGORITHM = "MD5WithRSA";

	private static final String PUBLIC_KEY = "RSAPublicKey";
	private static final String PRIVATE_KEY = "RSAPrivateKey";

	/**
	 * 获取公钥的字节长度
	 * 
	 * @param keyFactory
	 * @param key
	 * @return
	 */
	private static int getPublicKeyBitLength(KeyFactory keyFactory, Key key) {
		try {
			RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(key, RSAPublicKeySpec.class);
			return publicKeySpec.getModulus().bitLength();
		} catch (Exception e) {

		}
		return 2048;
	}

	/**
	 * 获取公钥加密可加密的最大数据字节长度
	 * 
	 * @param keyFactory
	 * @param key
	 * @return
	 */
	private static int getMaxEncryptBytesByPublicKey(KeyFactory keyFactory, Key key) {
		return getPublicKeyBitLength(keyFactory, key) / 8 - 11;
	}

	/**
	 * 加密<br>
	 * 用公钥加密
	 * 
	 * @param data
	 * @param key
	 *            Base64编码格式的公钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
		byte[] encryptedData = null;
		// 对公钥解码
		byte[] keyBytes = Base64Util.decode(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		int maxEncryptBlockSize = getMaxEncryptBytesByPublicKey(keyFactory, publicKey);
		System.out.println("加密公钥maxEncryptBlockSize：" + maxEncryptBlockSize);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {
			int dataLength = data.length;
			for (int i = 0; i < data.length; i += maxEncryptBlockSize) {
				int encryptLength = dataLength - i < maxEncryptBlockSize ? dataLength - i : maxEncryptBlockSize;
				byte[] doFinal = cipher.doFinal(data, i, encryptLength);
				bout.write(doFinal);
			}
			encryptedData = bout.toByteArray();
		} finally {
			if (bout != null) {
				bout.close();
			}
		}

		return encryptedData;
	}

	/**
	 * 获取私钥加密可加密的最大数据字节长度
	 * 
	 * @param keyFactory
	 * @param key
	 * @return
	 */
	private static int getMaxEncryptBytesByPrivate(KeyFactory keyFactory, Key key) {
		return getPrivateKeyBitLength(keyFactory, key) / 8 - 11;
	}

	/**
	 * 获取私钥的字节长度
	 * 
	 * @param keyFactory
	 * @param key
	 * @return
	 */
	private static int getPrivateKeyBitLength(KeyFactory keyFactory, Key key) {
		try {
			RSAPrivateKeySpec publicKeySpec = keyFactory.getKeySpec(key, RSAPrivateKeySpec.class);
			return publicKeySpec.getModulus().bitLength();
		} catch (Exception e) {

		}

		return 2048;
	}

	/**
	 * 加密<br>
	 * 用私钥加密
	 * 
	 * @param data
	 *            密文二进制数据
	 * @param key
	 *            BASE64编码的私钥字符串
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
		byte[] encryptedData = null;

		// 对密钥解码
		byte[] keyBytes = Base64Util.decode(key);

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);

		int maxEncryptBlockSize = getMaxEncryptBytesByPrivate(keyFactory, privateKey);
		System.out.println("加密私钥maxEncryptBlockSize:" + maxEncryptBlockSize);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {
			int dataLength = data.length;
			for (int i = 0; i < data.length; i += maxEncryptBlockSize) {
				int encryptLength = dataLength - i < maxEncryptBlockSize ? dataLength - i : maxEncryptBlockSize;
				byte[] doFinal = cipher.doFinal(data, i, encryptLength);
				bout.write(doFinal);
			}
			encryptedData = bout.toByteArray();
		} finally {
			if (bout != null) {
				bout.close();
			}
		}

		return encryptedData;
	}

	/**
	 * 用私钥对信息生成数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param privateKey
	 *            Base64编码格式的私钥
	 * 
	 * @return 经过Base64编码的字符串
	 * @throws Exception
	 */
	public static String sign(byte[] data, String privateKey) throws Exception {
		// 解码由base64编码的私钥
		byte[] keyBytes = Base64Util.decode(privateKey);

		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取私钥匙对象
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);

		return Base64Util.encode(signature.sign());
	}

	/**
	 * 获取私钥解密每块的字节长度
	 * 
	 * @param keyFactory
	 * @param key
	 * @return
	 */
	private static int getMaxDencryptBytesByPrivate(KeyFactory keyFactory, Key key) {
		return getPrivateKeyBitLength(keyFactory, key) / 8;
	}

	/**
	 * 解密<br>
	 * 用私钥解密
	 * 
	 * @param data
	 * @param key
	 *            Base64编码格式的私钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
		byte[] decryptedData = null;

		// 对密钥解码
		byte[] keyBytes = Base64Util.decode(key);

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		int maxDecryptBlockSize = getMaxDencryptBytesByPrivate(keyFactory, privateKey);
		System.out.println("解密私钥maxDecryptBlockSize：" + maxDecryptBlockSize);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {
			int dataLength = data.length;
			for (int i = 0; i < dataLength; i += maxDecryptBlockSize) {
				int decryptLength = dataLength - i < maxDecryptBlockSize ? dataLength - i : maxDecryptBlockSize;
				byte[] doFinal = cipher.doFinal(data, i, decryptLength);
				bout.write(doFinal);
			}
			decryptedData = bout.toByteArray();
		} finally {
			if (bout != null) {
				bout.close();
			}
		}

		return decryptedData;

	}

	/**
	 * 校验数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param publicKey
	 *            公钥
	 * @param sign
	 *            数字签名
	 * 
	 * @return 校验成功返回true 失败返回false
	 * @throws Exception
	 * 
	 */
	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {

		// 解码由base64编码的公钥
		byte[] keyBytes = Base64Util.decode(publicKey);

		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取公钥匙对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);

		// 验证签名是否正常
		return signature.verify(Base64Util.decode(sign));
	}

	/**
	 * 获取公钥解密每块的字节长度
	 * 
	 * @param keyFactory
	 * @param key
	 * @return
	 */
	private static int getMaxDencryptBytesByPublicKey(KeyFactory keyFactory, Key key) {
		return getPublicKeyBitLength(keyFactory, key) / 8;
	}

	/**
	 * 解密<br>
	 * 用公钥解密
	 * 
	 * @param data
	 * @param key
	 *            Base64编码格式的公钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
		byte[] decryptedData = null;

		// 对密钥解密
		byte[] keyBytes = Base64Util.decode(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicKey = keyFactory.generatePublic(x509KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);

		int maxDecryptBlockSize = getMaxDencryptBytesByPublicKey(keyFactory, publicKey);
		System.out.println("解密公鈅maxDecryptBlockSize:" + maxDecryptBlockSize);
		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		try {
			int dataLength = data.length;
			for (int i = 0; i < dataLength; i += maxDecryptBlockSize) {
				int decryptLength = dataLength - i < maxDecryptBlockSize ? dataLength - i : maxDecryptBlockSize;
				byte[] doFinal = cipher.doFinal(data, i, decryptLength);
				bout.write(doFinal);
			}
			decryptedData = bout.toByteArray();
		} finally {
			if (bout != null) {
				bout.close();
			}
		}

		return decryptedData;
	}

	/**
	 * 取得私钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);

		return Base64Util.encode(key.getEncoded());
	}

	/**
	 * 取得公钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);

		return Base64Util.encode(key.getEncoded());
	}

	/**
	 * 初始化密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(1024);// 2048 --解密公鈅maxDecryptBlockSize:256 1024 --解密私钥maxDecryptBlockSize：128

		KeyPair keyPair = keyPairGen.generateKeyPair();

		// 公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

		// 私钥
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		Map<String, Object> keyMap = new HashMap<String, Object>(2);

		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	public static String EncoderByMd5(String str) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		// 确定计算方法
		// MessageDigest md5 = MessageDigest.getInstance("MD5");

		// 加密后的字符串
		String newstr = Base64Util.encode(toMd5(str).getBytes("utf-8"));
		return newstr;
	}

	public static String toMd5(String str) {
		String re = null;
		byte encrypt[];
		try {
			byte[] tem = str.getBytes();
			MessageDigest md5 = MessageDigest.getInstance("md5");
			md5.reset();
			md5.update(tem);
			encrypt = md5.digest();
			StringBuilder sb = new StringBuilder();
			for (byte t : encrypt) {
				String s = Integer.toHexString(t & 0xFF);
				if (s.length() == 1) {
					s = "0" + s;
				}
				sb.append(s);
			}
			re = sb.toString();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return re;
	}
}
