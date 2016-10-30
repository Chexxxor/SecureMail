package keystore;

import java.io.*;
import java.security.*;

class GenSig {
	/* Generate a RSA signature */
	public static void main(String[] args) {
		try {
			if (args.length != 4) {
				System.out.println("Usage: GenSig datafile storefile alias storepass");
			}
			else try {
				signToFiles(args[0], args[1], args[2], args[3], "sig", "pubKey");
			} catch (Exception e) {
				System.err.println("Caught exception " + e.toString());
			}
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
	}

	public static byte[] sign(String dataFile, PrivateKey key) throws Exception {
		Signature rsa = Signature.getInstance("SHA256WITHRSA", "SunRsaSign");
		//Signature dsa = Signature.getInstance("SHA1WITHDSA", "SUN");
		rsa.initSign(key);
		FileInputStream fis = new FileInputStream(dataFile);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
			rsa.update(buffer, 0, len);
		};
		bufin.close();
		return rsa.sign();
	}
	public static byte[] sign(String dataFile, String storeFile, String alias, String storePass) throws Exception {
		PrivateKey prK = KeyLoader.getPrivate(storeFile, alias, storePass.toCharArray());

		byte[] signed = sign(dataFile, prK);
		return signed;
	}
	public static byte[] signToFiles(String dataFile, String storeFile, String alias, String storePass, String sigFileName, String pubKeyFileName) throws Exception {
		PublicKey puK = KeyLoader.getPublic(storeFile, alias, storePass.toCharArray());

		FileOutputStream keyfos = new FileOutputStream(pubKeyFileName);
		keyfos.write(puK.getEncoded());
		keyfos.close();

		FileOutputStream sigfos = new FileOutputStream(sigFileName);
		byte[] signed = sign(dataFile, storeFile, alias, storePass);
		sigfos.write(signed);
		sigfos.close();
		return signed;
	}
}