package com.samson.encrypt;

/**
 * @author - Chinaka .I. Light <ichinaka@byteworks.com.ng>
 * Date: 21/07/2021
 */
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 *
 * @author Light Chinaka
 */
public class EncryptKeyPairGenerator {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private String privateKeyPath;
    private String publicKeyPath;


    private static String ALGORITHM = "EC";

    // save private key for A and B
    String aPrivateKey = "A_ECC_Key.private";
    String bPrivateKey = "B_ECC_Key.private";

    String aPublicKey = "A_ECC_Key.public";
    String bPublicKey = "B_ECC_Key.public";

    KeyPair kpA;
    KeyPair kpB;
    ECPrivateKey aPrivKey;
    ECPublicKey aPubKey;

    ECPrivateKey bPriv;
    ECPublicKey bPub;

    public static String secretKeyPath = "secretKey.key";



    public EncryptKeyPairGenerator() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(256);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();

        this.privateKeyPath = ALGORITHM + "/PrivateKey";
        this.publicKeyPath =  ALGORITHM + "/PublicKey";

    }


    public void createECCKeyPairGenerator() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, Exception {
        // generate key pair
        //
        String name = "secp256k1";
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec curve = new ECGenParameterSpec(name);
        kpg.initialize(curve);

        kpA = kpg.genKeyPair();
        aPrivKey = (ECPrivateKey) kpA.getPrivate();
        aPubKey = (ECPublicKey) kpA.getPublic();


        kpB = kpg.genKeyPair();
        bPriv = (ECPrivateKey) kpB.getPrivate();
        bPub = (ECPublicKey) kpB.getPublic();

        writeToFile(aPrivateKey, aPrivKey.getEncoded());
        writeToFile(aPublicKey, aPubKey.getEncoded());

        String tmpSecretKey = "373874jkjkjkjk";

        String rsaEncryptedString = "";

        RSAKeyPairGenerator rsaKeyPairGen = new RSAKeyPairGenerator();
        rsaKeyPairGen.writePublicAndPrivateKeyToFile("_USER_A");
        rsaKeyPairGen.generateNewKeyPair();
        rsaKeyPairGen.writePublicAndPrivateKeyToFile("_USER_B");

        rsaKeyPairGen.readPublicAndPrivateKeyFromFile("_USER_A");
        rsaKeyPairGen.readPublicAndPrivateKeyFromFile("_USER_B");






        writeToFile(secretKeyPath, tmpSecretKey.getBytes() );





//        // Save A public Key
//        fos = new FileOutputStream(aPublicKey);
//        fos.write(aPubKey.getEncoded());
//        fos.close();
//
//        // Save B private Key
//        fos = new FileOutputStream(bPrivateKey);
//        fos.write(bPriv.getEncoded());
//        fos.close();
//
//        // Save B public Key
//        fos = new FileOutputStream(bPublicKey);
//        fos.write(bPub.getEncoded());
//        fos.close();


        writeToFile(bPrivateKey, bPriv.getEncoded());
        writeToFile(bPublicKey, bPub.getEncoded());

        // display private and public values for A
        //
        BigInteger S = aPrivKey.getS();
        ECPoint W = aPubKey.getW();
        BigInteger WX = W.getAffineX();
        BigInteger WY = W.getAffineY();

        System.out.println("User A");
        System.out.println("  S = " + S.toString(16));
        System.out.println("W.X = " + WX.toString(16));
        System.out.println("W.Y = " + WY.toString(16));


        //Display private and public values for B
        S = bPriv.getS();
        W = bPub.getW();
        WX = W.getAffineX();
        WY = W.getAffineY();

        System.out.println("User B");
        System.out.println("  S = " + S.toString(16));
        System.out.println("W.X = " + WX.toString(16));
        System.out.println("W.Y = " + WY.toString(16));

    }

    public static void main(String[] args) throws Exception {
        EncryptKeyPairGenerator e = new EncryptKeyPairGenerator();
        e.createECCKeyPairGenerator();

        String secretKey  = readStringFromFile(secretKeyPath);

        System.out.println("READING SECRET KEY FROM FILE: " + secretKey);


    }

    private static void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
//        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public void writePrivateKeyToFile(String path) throws IOException {
        this.writePrivateKeyToFile(path, getPrivateKey().getEncoded());
    }

    private void writePrivateKeyToFile(String path, byte[] key) throws IOException {
        this.privateKeyPath = path;
        this.writeToFile(this.privateKeyPath, key);
    }

    public void writePublicKeyToFile(String path) throws IOException {
        this.writePublicKeyToFile( path, getPublicKey().getEncoded() );
    }

    private void writePublicKeyToFile(String path, byte[] key) throws IOException {
        this.publicKeyPath = path;
        this.writeToFile(this.publicKeyPath, key);
    }

    public void writePublicAndPrivateKeyToFile(String prefix) throws IOException {
        this.writePrivateKeyToFile(this.privateKeyPath + prefix, getPrivateKey().getEncoded());
        this.writePublicKeyToFile(this.publicKeyPath + prefix, getPublicKey().getEncoded());
    }

    private static PKCS8EncodedKeySpec readFromFile(String path) throws Exception {
        File f = new File(path);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];

        String secretKeyHashed = String.valueOf(keyBytes);
        dis.readFully(keyBytes);
        dis.close();

        secretKeyHashed = new String(keyBytes, StandardCharsets.UTF_8);

        System.out.println("secretKeyHashed: " + secretKeyHashed);


        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return spec;
    }

    private static String readStringFromFile(String path) throws Exception {

        File f = new File(path);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];

        dis.readFully(keyBytes);
        dis.close();

        String secretKeyHashed = new String(keyBytes, StandardCharsets.UTF_8);

        System.out.println("secretKeyHashed: " + secretKeyHashed);
        return secretKeyHashed;

    }

    public static PrivateKey readPrivateKeyFromFile(String path) throws Exception {
        PKCS8EncodedKeySpec spec = readFromFile(path);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePrivate(spec);
    }

    public static PublicKey readPublicKeyFromFile(String path) throws Exception {
        PKCS8EncodedKeySpec spec = readFromFile(path);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec x509spec =
                new X509EncodedKeySpec(spec.getEncoded());
        System.out.println("==================================================\n" +
                "ENCODED-SPEC: " + Base64.getEncoder().encodeToString(x509spec.getEncoded()) +
                "\n==================================================\n"
        );
        return kf.generatePublic(x509spec);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

}

