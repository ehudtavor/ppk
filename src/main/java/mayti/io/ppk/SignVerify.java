package mayti.io.ppk;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

/*
* checkout the project README for details
*/
public class SignVerify {

    public static void main(String[] args) {

        try {
            new SignVerify().doLogic(args);
        } 
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void doLogic(String[] args) throws Exception {

        byte[] dataToSignAndVerify = "this data must be verified for integrity".getBytes("UTF8");

        // the KeyPair object in java provides all the PPK support we need
        KeyPair keyPair = createKeyPair();

        // sign the data using the private key
        byte[] signatureResult = doSign(dataToSignAndVerify, keyPair);

        // verify the signature with the public key
        Boolean verificationResult = doVerify(signatureResult, dataToSignAndVerify, keyPair);

        // debug printing using Base64 (to avoid print binary "characters")
        System.out.println("verification result: " + verificationResult);
    }

    private byte[] doSign(byte[] dataToSignAndVerify, KeyPair keyPair) throws Exception {

        // the Signature object in java provides all the signing support we need
        // we must decide upon creation what is the algo we use
        Signature signature = Signature.getInstance("SHA512withRSA");

        // setting the private key used to sign
        signature.initSign(keyPair.getPrivate());

        // setting the data to be signed
        signature.update(dataToSignAndVerify);

        // do signing, result is the signsature
        byte[] signatureResult = signature.sign();

        // debug printing using Base64 (to avoid print binary "characters")
        System.out.println("produced signature:" + Base64.getEncoder().encode(signatureResult));

        // return the signature
        return signatureResult;
    }

    private Boolean doVerify(byte[] signatureResult, byte[] dataToSignAndVerify, KeyPair keyPair) throws Exception {

        // the Signature object in java provides all the signing support we need
        // we must decide upon creation what is the algo we use
        Signature signature = Signature.getInstance("SHA512withRSA");

        // setting the public key used to verify
        signature.initVerify(keyPair.getPublic());

        // setting the data to be signed
        signature.update(dataToSignAndVerify);

        // do the verification, result is verified or not
        boolean verificationResult = signature.verify(signatureResult);

        // return the verification result
        return verificationResult;
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
