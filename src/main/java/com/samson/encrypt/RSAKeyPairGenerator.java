package com.samson.encrypt;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * @author - Chinaka .I. Light <ichinaka@byteworks.com.ng>
 * Date: 21/07/2021
 */
public class RSAKeyPairGenerator {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private String privateKeyPath;
    private String publicKeyPath;

    public static String AES_ALGORITHM = "AES";
    public static String RSA_ALGORITHM = "EC";

    private static String ALGORITHM = "RSA";

    private Map<String, PrivateKey> privateKeys =  new HashMap<>();
    private Map<String, PublicKey> publicKeys =  new HashMap<>();




    public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(2048);
    }
    private KeyPairGenerator keyGen;
    private KeyPair pair;

    public void generateNewKeyPair(){
        pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();

        this.privateKeyPath = ALGORITHM + "/PrivateKey";
        this.publicKeyPath =  ALGORITHM + "/PublicKey";
    }


    private void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public Map<String, PrivateKey> getPrivateKeys() {
        return privateKeys;
    }

    public void setPrivateKeys(Map<String, PrivateKey> privateKeys) {
        this.privateKeys = privateKeys;
    }

    public Map<String, PublicKey> getPublicKeys() {
        return publicKeys;
    }

    public void setPublicKeys(Map<String, PublicKey> publicKeys) {
        this.publicKeys = publicKeys;
    }


    public void writePrivateKeyToFile(String path) throws IOException {
        this.writePrivateKeyToFile(path, getPrivateKey().getEncoded());
    }

    private void writePrivateKeyToFile(String path, byte[] key) throws IOException {
//        this.privateKeyPath = path;
        this.writeToFile(path, key);
    }

    public void writePublicKeyToFile(String path) throws IOException {
        this.writePublicKeyToFile( path, getPublicKey().getEncoded() );
    }

    private void writePublicKeyToFile(String path, byte[] key) throws IOException {
//        this.publicKeyPath = path;
        this.writeToFile(path, key);
    }

    public void writePublicAndPrivateKeyToFile(String prefix) throws IOException {
        this.writePrivateKeyToFile(this.privateKeyPath + prefix, getPrivateKey().getEncoded());
        this.writePublicKeyToFile(this.publicKeyPath + prefix, getPublicKey().getEncoded());

        privateKeys.put(prefix, this.getPrivateKey());
        publicKeys.put(prefix, this.getPublicKey());
    }



    private PKCS8EncodedKeySpec readFromFile(String path) throws Exception {
        File f = new File(path);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        System.out.println("Listing the Providers");
        Arrays.stream(Security.getProviders()).forEach(eachProv -> {
            System.out.println(eachProv.getName());
        });
        return spec;
    }

    public void readPublicAndPrivateKeyFromFile(String prefix) throws Exception {
        this.privateKey = readPrivateKeyFromFile(this.privateKeyPath + prefix);
        this.publicKey = readPublicKeyFromFile(this.publicKeyPath + prefix);
        privateKeys.put(prefix, this.privateKey);
        publicKeys.put(prefix, this.publicKey);
    }


    public PrivateKey readPrivateKeyFromFile(String path) throws Exception {
        PKCS8EncodedKeySpec spec = readFromFile(path);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePrivate(spec);
    }

    public PublicKey readPublicKeyFromFile(String path) throws Exception {
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

