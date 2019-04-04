package mayti.io.ppk;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import javax.crypto.Cipher;

/*
* checkout the project README for details
*/
public class EncryptDecrypt {

    public static void main(String[] args) {

        try {
            new EncryptDecrypt().doLogic(args);
        } 
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void doLogic(String[] args) throws Exception {

        // the data we wish to encrypt
        byte[] dataToEncrypt = "this data should be encrypted ...".getBytes("UTF8");
        System.out.println("dataToEncrypt: " + new String(dataToEncrypt, StandardCharsets.UTF_8));

        // the KeyPair object provides the PPK support we need
        KeyPair keyPair = createKeyPair();

        // encrypt the data using the private key
        byte[] encryptResult = doEncrypt(dataToEncrypt, keyPair);

        // decrypt the encrypted data using the public key
        doDecrypt(encryptResult, keyPair);

    }

    private byte[] doEncrypt(byte[] dataToEncrypt, KeyPair keyPair) throws Exception {

        // the Cipher object provides the encrypt/decrypt support we need
        Cipher cipher = Cipher.getInstance("RSA");

        // set to encrypt operation, use Private Key
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        // encrypt the data
        byte[] encryptResult = cipher.doFinal(dataToEncrypt);

        // debug printing using Base64 (to avoid print binary "characters")
        System.out.println("encryptResult: " + Base64.getEncoder().encode(encryptResult));

        return encryptResult;

    }

    private void doDecrypt(byte[] encryptResult, KeyPair keyPair) throws Exception {

        // the Cipher object provides the encrypt/decrypt support we need
        Cipher cipher = Cipher.getInstance("RSA");

        // set to decrypt operation, use Public Key
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        // decrypt the encrypted data
        byte[] decryptResult = cipher.doFinal(encryptResult);

        // debug printing using Base64 (to avoid print binary "characters")
        System.out.println("decryptResult: " + new String(decryptResult, StandardCharsets.UTF_8));
    }

    /*
    * the simple way to create a PPK pair.
    * you could load a keystore you created using keytool.
    * you could load PEM (base64) private / public keys.
    */
    private KeyPair createKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.genKeyPair();
    }

}
