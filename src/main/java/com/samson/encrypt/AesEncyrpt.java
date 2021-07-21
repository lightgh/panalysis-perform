package com.samson.encrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileOutputStream;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;


/**
 * @author - Chinaka .I. Light
 * Date: 7/7/2020
 */
public class AesEncyrpt {

    private  String key;
    private  String initVector;
    private PublicKey pubKey;
    private PrivateKey privateKey;

    private SecretKey skey;
    private IvParameterSpec ivspec;

    private int bitSize;
    KeyGenerator kgen = null;

    public AesEncyrpt(){
        int aesSize = 128;
        this.intializeCall(aesSize);
        //Generate AES_ENCRYPTION SECRET KEY
    }

    private void printSecretAndIVKey() {
        System.out.println(Arrays.toString(skey.getEncoded()));
        System.out.println(Arrays.toString(ivspec.getIV()));
    }

    public void verifyAesKey(int aesBitSize, String aesKey) {
        this.verifyKeySize(aesBitSize, aesKey);
    }

    public AesEncyrpt(String aesKey){
        int length = Integer.parseInt(aesKey);
        System.out.println("KEY:::::::: " + aesKey);

        if(length != 128 && length != 192 && length != 256){
            throw new IllegalArgumentException("AESEncrypt Must Be Either of length 128, 192, or 256");
        }
        this.intializeCall(length);
    }

    private void intializeCall(int length) {
        this.bitSize = length;

        //Generate AES_ENCRYPTION SECRET KEY
        this.initializeKeyGen(bitSize);

        this.generateKey();

        this.generateInitVector();

        this.printSecretAndIVKey();

        this.verifyKeySizeAndVectorSizeNow(this.bitSize, this.key, this.initVector);
    }

    public void loadRSAPrivateKey(String pvtKeyFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = Files.readAllBytes(Paths.get(pvtKeyFilePath));
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        privateKey = kf.generatePrivate(ks);
    }

    public void loadRSAPublicKey(String pubKeyFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFilePath));
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        pubKey = kf.generatePublic(ks);
    }

    public void encryptSaveSecretKey(String toBeEncrptedAesSecretKeyFilePath) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        FileOutputStream out = new FileOutputStream(toBeEncrptedAesSecretKeyFilePath + ".enc");
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.pubKey ); // Encrypt using B's public key
            byte[] b = cipher.doFinal(this.skey.getEncoded());
            out.write(b);
        }

        out.write(this.ivspec.getIV());
    }

    public String encrypt(String value) {
        try {
            System.out.println("INIT_VECTOR::::: " + initVector);
            System.out.println("KEY::::: " + key);
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public void encryptFile(String originalFilePath, String toBeEncryptedOutputFilePath) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
//            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

            processFileEncryption(cipher, originalFilePath, toBeEncryptedOutputFilePath);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public String decrypt(String encrypted) {
        try {
            System.out.println("KEY-LENGTH: " + key.length());
            System.out.println("initVec-LENGTH: " + initVector.length());
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            System.out.println("BYTE_SIZE_DATA: " +  initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public String getKey(){ return this.key; }
    public String getInitVector(){ return this.initVector; }

    public void setKey(String key){
//        final int keySize = this.bitSize/8;
//        if( key.length() != keySize ){
//            throw new IllegalArgumentException("Key Must be of length " + keySize);
//        }
        this.key = key;
    }

    public void setInitVector(String initVector){
//        final int vectorSize = this.bitSize/8;
//        if( initVector.length() != vectorSize ){
//            throw new IllegalArgumentException("Init Vector (IV) must be of length " + vectorSize );
//        }
        this.initVector = initVector;
    }

    public void decryptFile(String encryptedFilePath, String decryptedFilePath) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            System.out.println("DF=BYTE_SIZE_DATA-IV: " +  initVector);
            System.out.println("DF=BYTE_SIZE_DATA: " +  initVector.getBytes("UTF-8"));
            System.out.println("DF=KEY-LENGTH: " + key.length());
            System.out.println("DF=initVec-LENGTH: " + initVector.length());

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
//            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            processFileEncryption(cipher, encryptedFilePath, decryptedFilePath);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }


    private void processFileEncryption(Cipher ci, String inFile, String outFile)
            throws AesCryptoException
    {
        File inputFile = new File(inFile);
        File outputFile = new File(outFile);

        try(FileInputStream in = new FileInputStream(inputFile);
            FileOutputStream out = new FileOutputStream(outputFile)){

            byte[] ibuf = new byte[(int)inputFile.length()];
            int len;
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = ci.update(ibuf, 0, len);
                if ( obuf != null ) out.write(obuf);
            }
            byte[] obuf = ci.doFinal(ibuf);
            if ( obuf != null ) out.write(obuf);
        }catch ( BadPaddingException
                | IllegalBlockSizeException | IOException ex ){
            throw new AesCryptoException("Error encrpting/decrpting file", ex);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

        AesEncyrpt aesEncyrpt = new AesEncyrpt();
        String originalString = "passwordLight343";
        System.out.println("Original String to encrypt - " + originalString);
        String encryptedString = aesEncyrpt.encrypt(originalString);
        System.out.println("Encrypted String - " + encryptedString);
        String decryptedString = aesEncyrpt.decrypt(encryptedString);
        System.out.println("After decryption - " + decryptedString);

        //TODO: Update Test Data with absolute file Path
        String originalFilePath = "C:\\Users\\Light Chinaka\\Documents\\files\\b\\Tuesday 24th September 2019 - Daily report.pdf";
        String toBeEncryptedOutputFilePath = "C:\\Users\\Light Chinaka\\Desktop\\Tuesday-24th-September-2019-DailyReport.pdf.encrypted";
        String deEncryptedOutputFilePath = "C:\\Users\\Light Chinaka\\Desktop\\Decrypted.pdf";

//        String originalFilePath = "C:\\Users\\Light Chinaka\\Desktop\\empty-file.txt";
//        String toBeEncryptedOutputFilePath = "C:\\Users\\Light Chinaka\\Desktop\\empty-file.txt.encrypted";
//        String deEncryptedOutputFilePath = "C:\\Users\\Light Chinaka\\Desktop\\empty-file.decrypted.txt";

        aesEncyrpt.encryptFile( originalFilePath, toBeEncryptedOutputFilePath );
        aesEncyrpt.decryptFile( toBeEncryptedOutputFilePath, deEncryptedOutputFilePath );

        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(Files.readAllBytes(Paths.get(toBeEncryptedOutputFilePath)));
        byte[] digest = md.digest();
        String myChecksum = DatatypeConverter
                .printHexBinary(digest).toUpperCase();
        System.out.println("MD5-Digest: " + myChecksum);

    }

    private boolean verifyKeySizeAndInitVectorSize(int bitSize, String key, String initVector) {
        final boolean isValidKeySize = verifyKeySize(bitSize, key);
        final boolean isValidVectorSize = verifyIVSize(bitSize, initVector);
        return isValidKeySize || isValidVectorSize;
    }



    private void verifyKeySizeAndVectorSizeNow(int bitSize, String key, String initVector) {
        if(this.verifyKeySizeAndInitVectorSize(bitSize, key, initVector)){
            throw new IllegalArgumentException("Invalid Key And Vector: Must Be Of Size " + bitSize/8 );
        }
    }

    private void initializeKeyGen(int bitSize) {
        try {
            this.kgen = KeyGenerator.getInstance("AES");
            this.kgen.init(this.bitSize);
            this.skey = this.kgen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
//        this.kgen.init(this.bitSize);
//        this.skey = this.kgen.generateKey();

    }

    private void generateKey() {
        this.key = Base64.getEncoder().encodeToString(this.skey.getEncoded());
        this.key = this.key.substring(this.key.length() - (this.bitSize/8));
    }

    private void generateInitVector() {
        SecureRandom secureRandom = new SecureRandom();
//        final int initVectorSize = this.bitSize/8;
        final int initVectorSize = 16;

        byte[] iv = new byte[initVectorSize];
        secureRandom.nextBytes(iv);
        this.ivspec = new IvParameterSpec(iv);
        this.initVector = Base64.getEncoder().encodeToString(ivspec.getIV());
        System.out.println("INITTTVECTOR-1: " + this.initVector);
        System.out.println("INITTTVECTOR-2: " + this.initVector.length());
        System.out.println("INITTTVECTOR-3: " + ivspec.getIV());
        this.initVector = this.initVector.substring(this.initVector.length() - (initVectorSize) );
    }

    private boolean verifyKeySize(int bitSize, String keyStr) {
        return bitSize / 8 != keyStr.length();
    }

    private boolean verifyIVSize(int bitSize, String initVector) {
        final int ivSize = 16; // bitSize / 8;
        return ivSize != initVector.length();
    }
}

class AesCryptoException extends Exception {

    public AesCryptoException() {
    }

    public AesCryptoException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
