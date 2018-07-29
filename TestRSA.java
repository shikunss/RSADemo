package com.sk.RSA;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Map;

public class TestRSA {
	private static String charset = "utf-8";
	private static String filePath = "D:/tmp/";

	public static void main(String[] args) throws Exception {
		/*
		 * RSA安全编码组件 1、生成公私钥对; //每次运行的结果都不同;考虑存下来 Map<String, Object> keyMap =
		 * RSAUtil.initKey(); String publickey = RSAUtil.getPublicKey(keyMap); String
		 * privatekey = RSAUtil.getPrivateKey(keyMap); 2、使用公钥加密，私钥解密
		 * encryptByPublicKey(byte[] data, String key) decryptByPrivateKey(byte[] data,
		 * String key) 3、使用私钥加密，公钥解密 encryptByPrivateKey(byte[] data, String key)
		 * decryptByPublicKey(byte[] data, String key) 4、使用私钥签名，公钥验签 sign(byte[] data,
		 * String privateKey) verify(byte[] data, String publicKey, String sign)
		 */

		Map<String, Object> keyMap = RSAUtil.initKey();
		String publickey = RSAUtil.getPublicKey(keyMap);
		String privatekey = RSAUtil.getPrivateKey(keyMap);

		String publicKeyString = publickey;
		System.out.println("public string:" + publicKeyString);

		String privateKeyString = privatekey;
		System.out.println("private string:" + privateKeyString);
		try {
			FileWriter pubfw = new FileWriter(filePath + "/publicKey.keystore");
			FileWriter prifw = new FileWriter(filePath + "/privateKey.keystore");
			BufferedWriter pubbw = new BufferedWriter(pubfw);
			BufferedWriter pribw = new BufferedWriter(prifw);
			pubbw.write(publicKeyString);
			pribw.write(privateKeyString);
			pubbw.flush();
			pubbw.close();
			pubfw.close();
			pribw.flush();
			pribw.close();
			prifw.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("--------------------公钥加密，私钥解密-----------");

		String plainText = "V7.5-T1-Icustomutils-S1522166400000-E1524758400000-F标准单点登录";
		byte[] cipherData = RSAUtil.encryptByPublicKey(plainText.getBytes(charset), publickey);
		String cipher = Base64Util.encode(cipherData);

		byte[] res = RSAUtil.decryptByPrivateKey(Base64Util.decode(cipher), privatekey);
		String restr = new String(res);

		System.out.println("原文：" + plainText);
		System.out.println("加密：" + cipher);
		System.out.println("解密：" + restr);
		System.out.println();
		System.out.println("--------------------私钥加密，公钥解密-----------");
		String plainText2 = "V7.5-T1-Icustomutils-S1522166400000-E1524758400000-F标准单点登录";
		cipherData = RSAUtil.encryptByPrivateKey(plainText2.getBytes(charset), privatekey);
		cipher = Base64Util.encode(cipherData);

		res = RSAUtil.decryptByPublicKey(Base64Util.decode(cipher), publickey);
		restr = new String(res);

		System.out.println("原文：" + plainText2);
		System.out.println("加密：" + cipher);
		System.out.println("解密：" + restr);
		System.out.println();

		System.out.println("--------------------私钥加密-----------");

		String syjac = "V7.5-T1-Icustomutils-S1522166400000-E1524758400000-F标准单点登录";
		byte[] cipherDatasa = RSAUtil.encryptByPrivateKey(syjac.getBytes(charset), privatekey);
		String ciphersa = Base64Util.encode(cipherDatasa);

		byte[] ressa = RSAUtil.decryptByPublicKey(Base64Util.decode(ciphersa), publickey);
		String restrsa = new String(ressa);
		System.out.println("加密：" + ciphersa);
		System.out.println("解密：" + restrsa);

		System.out.println("--------------------私钥签名-----------");
		String content = ciphersa;
		String signstr = RSAUtil.sign(Base64Util.decode(content), privatekey);
		System.out.println("原文：" + content);
		System.out.println("signature：" + signstr);
		System.out.println();

		System.out.println("原文content.getBytes(charset)：" + content.getBytes(charset).length);
		System.out.println("原文Base64Util.decode(content)：" + (Base64Util.decode(content)).length);

		System.out.println("---------------公钥验签------------------");
		System.out.println("原文：" + content);
		System.out.println("签名串：" + signstr);
		try {
			FileWriter pubfw = new FileWriter(filePath + "/加密原文.keystore");
			FileWriter prifw = new FileWriter(filePath + "/签名串.keystore");
			BufferedWriter pubbw = new BufferedWriter(pubfw);
			BufferedWriter pribw = new BufferedWriter(prifw);
			pubbw.write(content);
			pribw.write(signstr);
			pubbw.flush();
			pubbw.close();
			pubfw.close();
			pribw.flush();
			pribw.close();
			prifw.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("验证结果：" + RSAUtil.verify(Base64Util.decode(content), publickey, signstr));
		System.out.println();

		// 还原license;
		String license = "mLcZyZt/RY06cUmTgFSZkBYAWhEbkeLCEWXnbVGslY+LqmBUP0WtWzif+iYw2JXbSwlWZ2WdI2OLlhWHiAHaIWG4wxi8lvoHWnWhJbScHr0UklgkHISk+hs7731YrBfYbJXz7A8IZi5aZPvT86nSy8i4Ej9Vz8+1z7gXvF9FeWmzgxqfBI/WZRkxrRUPlwwpfNpqxC2fmYNMZ4q2DsDY36+25nGB7LnIbZYdm1fjthLLyfjfmvcIGrJhMwShiLRUfcamX6/H/1qdj6QVD5cy7iPhc0EE8mWNDIXL4c4p4/sVPXIE+E8nkvuCwnPx9J2jHMyJB3Bwd2bRMRNxWP3YjA==";
		String publicKey1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnWVuKbOcstCBEXZpTBIwKWkr3m1S0E5ELqFramOfaWmjYk4R+9ZhQkW6M/m7sQMWKGULkwfKVtnfDN22AV8RVKtaa+OZWvWZsRfEG26/kpbck3bdI+NPZakw86X9i1zKjf/mOZo7cX1NjmiAeOsx8H0UtpA5dpsOnyB1kc3phSnnFVQb4hiCf0EDIMY31YAqMpink/7KCas6+i2v9Nj2dStg9qEwLic5rqYqtd54Q6XDa0jWTa5+HprwL7WkbGcA3OBvBs/hDnT+qPw/702xCf+iRwfmYfNeslb4gYJL0lkcEgy4dGnLD2WraZFsnQKXHD7CO1jhq6GWAkle/8gYGwIDAQAB";
		String contentss = new String(RSAUtil.decryptByPublicKey(Base64Util.decode(license), publicKey1));
		System.out.println(contentss);
		// digest 怎么生成的；
		String digest = RSAUtil.EncoderByMd5(license);
		System.out.println("digest:" + digest);
		System.out.println(digest.length());
		System.out.println(
				"nD2u3+3AjZY6IJkeX3tI705zPBvmiPqAYq0c07xVYp9l/W7ekcN1sM7j6UorVWuOn7WaBTUWoVkeucNQDkiu6A==".length());
	}
}
