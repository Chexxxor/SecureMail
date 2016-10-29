package keystore;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.text.SimpleDateFormat;

public class VerSig {
    public static void main(String[] args) {

        /* Verify a DSA signature */

        if (args.length != 3) {
            System.out.println("Usage: VerSig " +
                "publickeyfile signaturefile " + "datafile");
        }
        else try {
        	boolean verifies = makeSignFromData(args[0], args[2]).verify(importSignFile(args[1]));

        	System.out.println("signature verifies: " + verifies);
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
    
    public static PublicKey importPublicKey(String filename) throws Exception {
    	FileInputStream keyfis = new FileInputStream(filename);
    	byte[] encKey = new byte[keyfis.available()];  
    	keyfis.read(encKey);
    	keyfis.close();
    	X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
    	//KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
    	return keyFactory.generatePublic(pubKeySpec);
    }
    
    public static byte[] importSignFile(String filename) throws Exception {
      	FileInputStream sigfis = new FileInputStream(filename);
    	byte[] sigToVerify = new byte[sigfis.available()]; 
    	sigfis.read(sigToVerify);
    	sigfis.close();
    	return sigToVerify;
    }
    
    public static Signature makeSignFromData(String keyFile, String dataFile) throws Exception {
    	Signature sig = Signature.getInstance("SHA256WITHRSA", "SunRsaSign");
    	sig.initVerify(importPublicKey(keyFile));
    	
    	FileInputStream datafis = new FileInputStream(dataFile);
    	BufferedInputStream bufin = new BufferedInputStream(datafis);

    	byte[] buffer = new byte[1024];
    	int len;
    	while (bufin.available() != 0) {
    	    len = bufin.read(buffer);
    	    sig.update(buffer, 0, len);
    	};
    	bufin.close();

    	return sig;
    }
}
