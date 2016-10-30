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
				PrivateKey prK = KeyLoader.getPrivate(args[1], args[2], args[3].toCharArray());
				PublicKey puK = KeyLoader.getPublic(args[1], args[2], args[3].toCharArray());
				/* save the signature in a file */
				FileOutputStream sigfos = new FileOutputStream("sign");
				sigfos.write(sign(args[0], prK));
				sigfos.close();
				
				/* save the public key in a file */
				byte[] key = puK.getEncoded();
				FileOutputStream keyfos = new FileOutputStream("pubKey");
				keyfos.write(key);
				keyfos.close();			} catch (Exception e) {
				System.err.println("Caught exception " + e.toString());
			}
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
	}
	
	public static byte[] sign(String message, PrivateKey key) throws Exception {
		Signature rsa = Signature.getInstance("SHA256WITHRSA", "SunRsaSign");
		//Signature dsa = Signature.getInstance("SHA1WITHDSA", "SUN");
		rsa.initSign(key);
		FileInputStream fis = new FileInputStream(message);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
		    rsa.update(buffer, 0, len);
		};
		bufin.close();
		return rsa.sign();
	}
}