package rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RsaTest {
	
	static final String SAMPLE_TEXT = "O2OSYS";
	static final byte[] SAMPLE_DATA = SAMPLE_TEXT.getBytes(StandardCharsets.UTF_8);
	static final int RSA_KEY_BIT_SIZE = 2048;
	
	static final int FILE_BUFFER_SIZE = 2048;
	
	public static void main(String[] args) {
		byte[] privateKeyData = null;
		byte[] publicKeyData = null;
		File privateKeyFile = new File(getKeyDirectory() + "java.rsa.private.key");
		File publicKeyFile = new File(getKeyDirectory() + "java.rsa.public.key");
		if (privateKeyFile.exists() && publicKeyFile.exists()) {
			// 파일이 있으면 로드
			privateKeyData = Base64.getDecoder().decode(readAllText(privateKeyFile));
			publicKeyData = Base64.getDecoder().decode(readAllText(publicKeyFile));
		}
		else {
			// 파일이 없으면 새로 생성
			KeyPair keyPair;
			try {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(RSA_KEY_BIT_SIZE, new SecureRandom());
				keyPair = keyGen.genKeyPair();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return;
			}
			privateKeyData = keyPair.getPrivate().getEncoded();
			writeAllText(privateKeyFile, Base64.getEncoder().encodeToString(privateKeyData));
			publicKeyData = keyPair.getPublic().getEncoded();
			writeAllText(publicKeyFile, Base64.getEncoder().encodeToString(publicKeyData));
		}
		
		// 공개키로 암호화
		byte[] encryptedData = encrypt(SAMPLE_DATA, publicKeyData);
		File encryptedFile = new File(getKeyDirectory() + "java.rsa.data");
		writeAllText(encryptedFile, Base64.getEncoder().encodeToString(encryptedData));
		
		// 개인키로 복호화
		byte[] decryptedData = decrypt(encryptedData, privateKeyData);
		
		// 결과
		System.out.println("---------- RSA, Key: Java, Endec: Java ----------");
		System.out.println("Original Data : " + Base64.getEncoder().encodeToString(SAMPLE_DATA));
		System.out.println("Decrypted Data: " + Base64.getEncoder().encodeToString(decryptedData));
	}
	
	private static byte[] encrypt(byte[] data, byte[] publicKeyData) {
		byte[] encryptedData = null;
		try {
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			Cipher encryptor = Cipher.getInstance("RSA");
			encryptor.init(Cipher.ENCRYPT_MODE, publicKey);
			encryptedData = encryptor.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return encryptedData;
	}

	private static byte[] decrypt(byte[] data, byte[] privateKeyData) {
		byte[] decryptedData = null;
		try {
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			Cipher decryptor = Cipher.getInstance("RSA");
			decryptor.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedData = decryptor.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return decryptedData;
	}
	
	private static String getKeyDirectory() {
		return System.getProperty("user.dir") + File.separator;
	}
	
	private static String readAllText(File file) {
		String result = null;
		
		try (FileReader fr = new FileReader(file)) {
			StringBuilder sb = new StringBuilder(FILE_BUFFER_SIZE);
			try (BufferedReader br = new BufferedReader(fr)) {
				String line = null;
				while ((line = br.readLine()) != null) {
					sb.append(line);
				}
			}
			result = sb.toString();
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		
		return result;
	}
	
	private static void writeAllText(File file, String text) {
		try (FileWriter fw = new FileWriter(file)) {
			try (BufferedWriter bw = new BufferedWriter(fw)) {
				bw.write(text);
			}
		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}
}
