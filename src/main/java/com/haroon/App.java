package com.haroon;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.examples.RSAKeyPairGenerator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.util.Date;

/**
 * Hello world!
 *
 */
public class App 
{
    private boolean isArmored = false;
    private String id = "damico";
    private String passwd = "test";
    private boolean integrityCheck = true;


    private String pubKeyFile = "/tmp/pub.dat";
    //private String pubKeyFile   = "/Users/haroon/.ssh/id_rsa.pub";
    private String privKeyFile = "/tmp/secret.dat";

    private String plainTextFile = "/tmp/plain-text.txt"; //create a text file to be encripted, before run the tests
    private String cipherTextFile = "/tmp/cypher-text.dat";
    private String decPlainTextFile = "/tmp/dec-plain-text.txt";
    private String signatureFile = "/tmp/signature.txt";
    public static void main( String[] args ) throws Exception {
        System.out.println( "Hello World!" );
        App app = new App();
        //app.genKeyPair();
        //app.encrypt();
        app.decrypt();
    }


    public void encrypt() throws NoSuchProviderException, IOException, PGPException {
        FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
        FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
        PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
        cipheredFileIs.close();
        pubKeyIs.close();
    }


    public void decrypt() throws Exception{

        FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
        FileInputStream privKeyIn = new FileInputStream(privKeyFile);
        FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
        PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
        cipheredFileIs.close();
        plainTextFileIs.close();
        privKeyIn.close();
    }

    public void genKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(1024);

        KeyPair                    kp = kpg.generateKeyPair();

        FileOutputStream    out1 = new FileOutputStream(privKeyFile);
        FileOutputStream    out2 = new FileOutputStream(pubKeyFile);


                exportKeyPair(out1, out2, kp,id, passwd.toCharArray(), isArmored);


    }

    public  void exportKeyPair(OutputStream var0, OutputStream var1, KeyPair var2, String var3, char[] var4, boolean var5) throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
        if (var5) {
            var0 = new ArmoredOutputStream((OutputStream)var0);
        }

        PGPDigestCalculator var6 = (new JcaPGPDigestCalculatorProviderBuilder()).build().get(2);
        JcaPGPKeyPair var7 = new JcaPGPKeyPair(1, var2, new Date());
        PGPSecretKey var8 = new PGPSecretKey(16, var7, var3, var6, (PGPSignatureSubpacketVector)null, (PGPSignatureSubpacketVector)null, new JcaPGPContentSignerBuilder(var7.getPublicKey().getAlgorithm(), 2), (new JcePBESecretKeyEncryptorBuilder(3, var6)).setProvider("BC").build(var4));
        var8.encode((OutputStream)var0);
        ((OutputStream)var0).close();
        if (var5) {
            var1 = new ArmoredOutputStream((OutputStream)var1);
        }

        PGPPublicKey var9 = var8.getPublicKey();
        var9.encode((OutputStream)var1);
        ((OutputStream)var1).close();
    }
}
