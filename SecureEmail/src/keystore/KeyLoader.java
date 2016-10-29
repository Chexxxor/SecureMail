package keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class KeyLoader {
	static String ksName = "keystore";
	static String tsName = "truststore";
	static char[] spass = {'M', 'y', 'P', 'a', 's', 's'};
	
	public static PublicKey getPublic(String name) throws Exception {
		return loadStore(ksName).getCertificate(name).getPublicKey();
	}
	
	public static PrivateKey getPrivate(String name) throws Exception {
		return (PrivateKey) loadStore(ksName).getKey(name, spass);
	}
	
	public static KeyStore loadStore(String storeName) throws Exception { 
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream ksfis = new FileInputStream(storeName);
		BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
		ks.load(ksbufin, spass);
		return ks;
	}
}
