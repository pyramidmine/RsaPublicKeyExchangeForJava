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
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RsaTest {
	
	static final String SAMPLE_TEXT = "O2OSYS";
	static final byte[] SAMPLE_DATA = SAMPLE_TEXT.getBytes(StandardCharsets.UTF_8);
	static final int RSA_KEY_BIT_SIZE = 2048;
	static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
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
		System.out.println("---------- RSA, Key: Java, Apply: Java ----------");
		System.out.println("Original Data : " + Base64.getEncoder().encodeToString(SAMPLE_DATA));
		System.out.println("Decrypted Data: " + Base64.getEncoder().encodeToString(decryptedData));

		// Signing/Verification
		System.out.println("---------- RSA Signing/Verification, Key: Java, Apply: Java ----------");
		byte[] signature = sign(SAMPLE_DATA, SIGNATURE_ALGORITHM, privateKeyData);
		
		// Verification
		boolean verified = verify(SAMPLE_DATA, SIGNATURE_ALGORITHM, signature, publicKeyData);
		System.out.println("Original Data Verification: " + verified);
		
		// 조작된 데이터로 검증
		byte[] fakeSampleData = Arrays.copyOf(SAMPLE_DATA, SAMPLE_DATA.length);
		fakeSampleData[5] += 1;
		verified = verify(fakeSampleData, SIGNATURE_ALGORITHM, signature, publicKeyData);
		System.out.println("Fake Data Verification: " + verified);
	}
	
	private static byte[] encrypt(byte[] data, byte[] publicKeyData) {
		byte[] encryptedData = null;
		try {
			PublicKey publicKey = createPublicKey(publicKeyData);
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
		}
		return encryptedData;
	}

	private static byte[] decrypt(byte[] data, byte[] privateKeyData) {
		byte[] decryptedData = null;
		try {
			PrivateKey privateKey = createPrivateKey(privateKeyData);
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
		}
		return decryptedData;
	}
	
	private static byte[] sign(byte[] data, String algorithm, byte[] privateKeyData) {
		byte[] result = null;
		try {
			PrivateKey privateKey = createPrivateKey(privateKeyData);
			Signature signature = Signature.getInstance(algorithm);
			signature.initSign(privateKey);
			signature.update(data);
			result = signature.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return result;
	}
	
	private static boolean verify(byte[] data, String algorithm, byte[] signedData, byte[] publicKeyData) {
		boolean result = false;
		try {
			PublicKey publicKey = createPublicKey(publicKeyData);
			Signature signature = Signature.getInstance(algorithm);
			signature.initVerify(publicKey);
			signature.update(data);
			result = signature.verify(signedData);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return result;
	}
	
	private static PrivateKey createPrivateKey(byte[] privateKeyData) {
		PrivateKey privateKey = null;
		try {
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(privateKeySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return privateKey;
	}
	
	private static PublicKey createPublicKey(byte[] publicKeyData) {
		PublicKey publicKey = null;
		try {
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(publicKeySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return publicKey;
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
