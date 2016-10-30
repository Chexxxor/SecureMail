package keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyLoader {
	public static PublicKey getPublic(String store, String alias, char [] pass) throws Exception {
		return loadStore(store, pass).getCertificate(alias).getPublicKey();
	}
	
	public static PrivateKey getPrivate(String store, String alias, char[] pass) throws Exception {
		return (PrivateKey) loadStore(store, pass).getKey(alias, pass);
	}
	
	public static KeyStore loadStore(String storeName, char[] pass) throws Exception { 
		KeyStore ks = KeyStore.getInstance("JKS");
		FileInputStream ksfis = new FileInputStream(storeName);
		BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
		ks.load(ksbufin, pass);
		return ks;
	}
}
