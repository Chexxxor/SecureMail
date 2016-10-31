package keystore;

import java.io.*;
import java.security.*;
import java.security.spec.*;

public class VerSig {
	public static void main(String[] args) {

		/* Verify a RSA signature */

		if (args.length != 3 && args.length != 5) {
			System.out.println("Usage:\tVerSig datafile signaturefile keyfile");
			System.out.println("\tVerSig datafile signaturefile keystorefile alias storepass");
		}
		else try {
			boolean verifies;
			if(args.length == 5)
				verifies = verify(args[0], args[1], args[2], args[3], args[4]);
			else
				verifies = verify(args[0], args[1], args[2]);
			System.out.println("signature verifies: " + verifies);
		} catch (Exception e) {
			System.err.println("Caught exception " + e.toString());
			System.out.println("Usage:\tVerSig datafile signaturefile keyfile");
			System.out.println("\tVerSig datafile signaturefile keystorefile alias storepass");
		}
	}
	
	public static boolean verify(String dataFile, String signFile, PublicKey key) throws Exception {
		return makeSignFromData(key, dataFile).verify(importSignFile(signFile));
	}
	public static boolean verify(String dataFile, String signFile, String keyFile) throws Exception {
		return verify(dataFile, signFile, importPublicKey(keyFile));
	}
	public static boolean verify(String dataFile, String signFile, String keyStoreFile, String alias, String storePass) throws Exception {
		PublicKey key = KeyLoader.getPublic(keyStoreFile, alias, storePass.toCharArray());
		return verify(dataFile, signFile, key);
	}

	private static PublicKey importPublicKey(String filename) throws Exception {
		FileInputStream keyfis = new FileInputStream(filename);
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		keyfis.close();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
		//KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
		return keyFactory.generatePublic(pubKeySpec);
	}
	private static byte[] importSignFile(String filename) throws Exception {
		FileInputStream sigfis = new FileInputStream(filename);
		byte[] sigToVerify = new byte[sigfis.available()]; 
		sigfis.read(sigToVerify);
		sigfis.close();
		return sigToVerify;
	}
	private static Signature makeSignFromData(PublicKey key, String dataFile) throws Exception {
		Signature sig = Signature.getInstance("SHA256WITHRSA", "SunRsaSign");
		//Signature sig = Signature.getInstance("SHA1WITHDSA", "SUN");
		sig.initVerify(key);

		FileInputStream datafis = new FileInputStream(dataFile);
		BufferedInputStream bufin = new BufferedInputStream(datafis);

		byte[] buffer = new byte[1024];
		int len;
		while (bufin.available() != 0) {
			len = bufin.read(buffer);
			sig.update(buffer, 0, len);
		};
		bufin.close();

		return sig;    }
}
