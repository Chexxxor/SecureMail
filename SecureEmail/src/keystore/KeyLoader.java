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
	static char[] spass = {'M', 'y', 'P', 'a', 's', 's'};
	
	public static PublicKey getPublic(String name) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		return loadStore().getCertificate(name).getPublicKey();
	}
	
	public static PrivateKey getPrivate(String name) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		return (PrivateKey) loadStore().getKey(name, spass);
	}
	
	public static KeyStore loadStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{ 
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream ksfis = new FileInputStream(ksName);
		BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
		ks.load(ksbufin, spass);
		return ks;
	}
}
