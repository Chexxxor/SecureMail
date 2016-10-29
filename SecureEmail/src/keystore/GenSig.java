package keystore;

import java.io.*;
import java.security.*;

class GenSig {

    public static void main(String[] args) {

        /* Generate a DSA signature */

        if (args.length != 1) {
            System.out.println("Usage: GenSig nameOfFileToSign");
        }
        else try {
        	Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        } catch (Exception e) {
            System.err.println("Caught exception " + e.toString());
        }
    }
}