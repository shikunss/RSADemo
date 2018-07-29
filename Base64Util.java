package com.sk.RSA;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import org.apache.commons.codec.binary.Base64;

public class Base64Util {
	public static byte[] decode(String base64) throws UnsupportedEncodingException {
		String plainTextEncode =

				// ConfigUtil.get().getProperty("plain.text.encode", "UTF-8");
				"UTF-8";
		return Base64.decodeBase64(base64.getBytes(plainTextEncode));
	}

	public static byte[] decode(byte[] bytes) throws Exception {
		return Base64.decodeBase64(bytes);
	}

	public static String encode(byte[] bytes) throws UnsupportedEncodingException {
		String plainTextEncode =
				// ConfigUtil.get().getProperty("plain.text.encode", "UTF-8");
				"UTF-8";
		return new String(Base64.encodeBase64(bytes), plainTextEncode);
	}

	public static String encodeFile(String filePath) throws Exception {
		byte[] bytes = fileToByte(filePath);
		return encode(bytes);
	}

	public static void decodeToFile(String filePath, String base64) throws Exception {
		byte[] bytes = decode(base64);
		byteArrayToFile(bytes, filePath);
	}

	public static byte[] fileToByte(String filePath) throws Exception {
		byte[] data = new byte[0];
		File file = new File(filePath);

		int cacheSize = 1024;
		// ConfigUtil.get().getIntegerProperty("cache.size",
		// Integer.valueOf(1024)).intValue();

		if (file.exists()) {
			FileInputStream in = new FileInputStream(file);
			ByteArrayOutputStream out = new ByteArrayOutputStream(2048);
			byte[] cache = new byte[cacheSize];
			int nRead = 0;

			while ((nRead = in.read(cache)) != -1) {
				out.write(cache, 0, nRead);
				out.flush();
			}

			out.close();
			in.close();
			data = out.toByteArray();
		}

		return data;
	}

	public static void byteArrayToFile(byte[] bytes, String filePath) throws Exception {
		InputStream in = new ByteArrayInputStream(bytes);
		File destFile = new File(filePath);

		int cacheSize = 1024;
		// ConfigUtil.get().getIntegerProperty("cache.size",
		// Integer.valueOf(1024)).intValue();

		if (!destFile.getParentFile().exists()) {
			destFile.getParentFile().mkdirs();
		}

		destFile.createNewFile();
		OutputStream out = new FileOutputStream(destFile);
		byte[] cache = new byte[cacheSize];
		int nRead = 0;

		while ((nRead = in.read(cache)) != -1) {
			out.write(cache, 0, nRead);
			out.flush();
		}

		out.close();
		in.close();
	}
}