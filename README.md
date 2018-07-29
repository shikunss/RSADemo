# RSADemo
  
RSA安全编码组件  
1、生成公私钥对;     
Map<String, Object> keyMap = RSAUtil.initKey();   
String publickey = RSAUtil.getPublicKey(keyMap);   
String privatekey = RSAUtil.getPrivateKey(keyMap);   
2、使用公钥加密，私钥解密   
encryptByPublicKey(byte[] data,String key)   
decryptByPrivateKey(byte[] data, String key)   
3、使用私钥加密，公钥解密  
encryptByPrivateKey(byte[] data, String key)   
decryptByPublicKey(byte[] data,String key)   
4、使用私钥签名，公钥验签   
sign(byte[] data, String privateKey)   
verify(byte[] data, String publicKey, String sign)  
