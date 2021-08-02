package com.samson.controller;

import com.samson.PerformantMetricsApp;
import com.samson.encrypt.*;
import com.samson.utils.MetricsMeasurement;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.fxml.Initializable;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Random;
import java.util.ResourceBundle;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.Region;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;

/**
 * @author - Chinaka .I. Light <ichinaka@byteworks.com.ng>
 * Date: 21/07/2021
 */
public class MainViewController implements Initializable {

    @FXML
    public Button buttonEncryptFileTrigger;

//    @FXML
    public TextField hiddenTextFieldIV;
    
    public TextField textFieldEncryptionInitVector;
    public TextField textFieldDecryptionInitVector;
    public Button btnClearDecrypt;
    public Button btnClearEncrypt;


    @FXML
    private ResourceBundle resources;

    @FXML
    private URL location;

    @FXML
    private Button buttonGenerateKeyPairAndSecretKey;

    @FXML
    private TextField textFieldFileToEncrypt;

    @FXML
    private Button buttonBrowseFileToEncrypt;

    @FXML
    private TextField textFieldEncryptedFileDestination;

    @FXML
    private TextField textFieldEncryptionSecretKey;

    @FXML
    private TextField textFieldEncryptionEncryptedSecretKey;

    @FXML
    private TextField textFieldEncryptionHash;

    @FXML
    private TextField textFieldEncryptionDigitalSignature;

    @FXML
    private RadioButton radioButtonEncryptFileEncryptOnly;

    @FXML
    private RadioButton radioButtonEncryptFileEncryptWithSignatureVerification;

    @FXML
    private TextField textFieldEncryptedFileToDecrypt;

    @FXML
    private Button buttonBrowseEncryptedFileToDecrypt;

    @FXML
    private TextField textFieldDecryptedFileDestination;

    @FXML
    private TextField textFieldDecryptionHash;

    @FXML
    private TextField textFieldDecryptedDigitalSignature;

    @FXML
    private Button buttonDecryptFileTrigger;

    @FXML
    private RadioButton radioButtonDecryptFileDecryptOnly;

    @FXML
    private RadioButton radioButtonDecryptFileDecryptWithSignatureVerification;

    ToggleGroup encryptToggleOption;

    ToggleGroup decryptToggleOption;

    String encryptionMeasurementType;

    String decryptionMeasurementType;

    private PublicKey tmpRSAPublicKey_A;
    private PrivateKey tmpRSAPrivateKey_A;

    private PublicKey tmpRSAPublicKey_B;
    private PrivateKey tmpRSAPrivateKey_B;

    private File selectedFile;
    private File selectedEncryptedFileDestination;
    private String messageDigest;

    private  AesEncyrpt aesEncyrpt;

    private Logger LOGGER = LoggerFactory.getLogger(MainViewController.class);

    Alert alertInfo = new Alert(Alert.AlertType.INFORMATION);

    long fileEncryptionTime;
    long fileEncryptionMemoryUsage;
    long fileEncryptionSignatureVerificationTime;
    long fileEncryptionSignatureVerificationMemoryUsage;


    long fileDecryptionTime;
    long fileDecryptionMemoryUsage;
    long fileDecryptionSignatureVerificationTime;
    long fileDecryptionSignatureVerificationMemoryUsage;
    private Stage browseFileToDecryptStage;
    private FileChooser fileChooserDecrypt;


    @FXML
    void initialize() {
        assert buttonGenerateKeyPairAndSecretKey != null : "fx:id=\"buttonGenerateKeyPairAndSecretKey\" was not " +
                "injected: check your FXML file 'MainView.fxml'.";
        assert textFieldFileToEncrypt != null : "fx:id=\"textFieldFileToEncrypt\" was not injected: check your FXML " +
                "file 'MainView.fxml'.";
        assert buttonBrowseFileToEncrypt != null : "fx:id=\"buttonBrowseFileToEncrypt\" was not injected: check your " +
                "FXML file 'MainView.fxml'.";
        assert textFieldEncryptedFileDestination != null : "fx:id=\"textFieldEncryptedFileDestination\" was not " +
                "injected: check your FXML file 'MainView.fxml'.";
        assert textFieldEncryptionSecretKey != null : "fx:id=\"textFieldEncryptionSecretKey\" was not injected: check" +
                " your FXML file 'MainView.fxml'.";
        assert textFieldEncryptionEncryptedSecretKey != null : "fx:id=\"textFieldEncryptionEncryptedSecretKey\" was " +
                "not injected: check your FXML file 'MainView.fxml'.";
        assert textFieldEncryptionHash != null : "fx:id=\"textFieldEncryptionHash\" was not injected: check your FXML" +
                " file 'MainView.fxml'.";
        assert textFieldEncryptionDigitalSignature != null : "fx:id=\"textFieldEncryptionDigitalSignature\" was not " +
                "injected: check your FXML file 'MainView.fxml'.";
        assert radioButtonEncryptFileEncryptOnly != null : "fx:id=\"radioButtonEncryptFileEncryptOnly\" was not " +
                "injected: check your FXML file 'MainView.fxml'.";
        assert radioButtonEncryptFileEncryptWithSignatureVerification != null : "fx:id" +
                "=\"radioButtonEncryptFileEncryptWithSignatureVerification\" was not injected: check your FXML file " +
                "'MainView.fxml'.";
        assert textFieldEncryptedFileToDecrypt != null : "fx:id=\"textFieldEncryptedFileToDecrypt\" was not injected:" +
                " check your FXML file 'MainView.fxml'.";
        assert buttonBrowseEncryptedFileToDecrypt != null : "fx:id=\"buttonBrowseEncryptedFileToDecrypt\" was not " +
                "injected: check your FXML file 'MainView.fxml'.";
        assert textFieldDecryptedFileDestination != null : "fx:id=\"textFieldDecryptedFileDestination\" was not " +
                "injected: check your FXML file 'MainView.fxml'.";
        assert textFieldDecryptionHash != null : "fx:id=\"textFieldDecryptionHash\" was not injected: check your FXML" +
                " file 'MainView.fxml'.";
        assert textFieldDecryptedDigitalSignature != null : "fx:id=\"textFieldDecryptedDigitalSignature\" was not " +
                "injected: check your FXML file 'MainView.fxml'.";
        assert buttonDecryptFileTrigger != null : "fx:id=\"buttonDecryptFileTrigger\" was not injected: check your " +
                "FXML file 'MainView.fxml'.";
        assert radioButtonDecryptFileDecryptOnly != null : "fx:id=\"radioButtonDecryptFileDecryptOnly\" was not " +
                "injected: check your FXML file 'MainView.fxml'.";
        assert radioButtonDecryptFileDecryptWithSignatureVerification != null : "fx:id" +
                "=\"radioButtonDecryptFileDecryptWithSignatureVerification\" was not injected: check your FXML file " +
                "'MainView.fxml'.";

        setup();

    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        setup();
    }

    public void setup() {

        // setup radio Button
        setUpMeasurementTypeHandler();
        buttonEncryptFileTrigger.setDisable(true);

        //Generate Key On Button Click
        setupGenerateKeyHandler();

        //Setup Handlers....
        setupEncryptFileTriggerHandler();

        setupBrowseFileToEncryptHandler();

        setupBrowseFileToDecryptHandler();

        setupDecryptFileTriggerHandler();

    }

    private void setupDecryptFileTriggerHandler() {
        buttonDecryptFileTrigger.setOnAction(event -> {
            try {
                if(alertInfo == null){
                    alertInfo = new Alert(Alert.AlertType.INFORMATION);
                }

                PerformantMetricsApp.setDialogIcon(alertInfo);

                // TODO add your handling code here:
                if(this.textFieldEncryptedFileToDecrypt.getText() == null || this.textFieldEncryptedFileToDecrypt.getText().trim().isEmpty()){
                    alertInfo.setContentText("Please File Select Encrypted File TO Decrypt");
                    alertInfo.getDialogPane().setPrefHeight(Region.USE_PREF_SIZE);
                    alertInfo.showAndWait();
                    return;
                }

                if(this.textFieldDecryptedFileDestination.getText() == null || this.textFieldDecryptedFileDestination.getText().trim().isEmpty()){
                    alertInfo.setContentText("Please Destination Of Decrypted File");
                    alertInfo.getDialogPane().setPrefHeight(Region.USE_PREF_SIZE);
                    alertInfo.showAndWait();
                    return;
                }

                String initVectorH = this.textFieldDecryptionInitVector.getText();

                if(initVectorH == null || initVectorH.length() == 8){
                    System.out.println( "initVectorH: " + initVectorH );
                }

                String signECDSAStr = textFieldDecryptedDigitalSignature.getText();
                String myCheckSumStr = textFieldDecryptionHash.getText();

                MetricsMeasurement sigverifyM = MetricsMeasurement.startMM();

                boolean verifyECDSA = ECDSAHelper.verifyECDSA(publicKeyAEcc, signECDSAStr, myCheckSumStr);

                if(!verifyECDSA){
                    alertInfo.setHeaderText("Can't Proceed With Decryption");
                    alertInfo.setContentText("As The Source Of the File Cant Be Verified");
                    alertInfo.getDialogPane().setPrefHeight(Region.USE_PREF_SIZE);
                    alertInfo.showAndWait();
                    return;
                }



                String aesSecretKey = this.performDecryptionOfAESSecretKeyWithRSA(this.tmpRSAPrivateKey_B);

                sigverifyM.stop();
                fileDecryptionSignatureVerificationMemoryUsage = sigverifyM.getMemoryUsed();
                fileEncryptionSignatureVerificationTime = sigverifyM.getTimeDifference();


                File fileToCheck = new File(this.textFieldEncryptedFileToDecrypt.getText());
                File decryptedDestination =  new File(textFieldDecryptedFileDestination.getText());


                MetricsMeasurement decryptM = MetricsMeasurement.startMM();

                aesEncyrpt.setKey(aesSecretKey);
                aesEncyrpt.setInitVector(initVectorH);

                aesEncyrpt.decryptFile(fileToCheck.getAbsolutePath(), decryptedDestination.getAbsolutePath());
                decryptM.stop();
                fileDecryptionMemoryUsage = decryptM.getMemoryUsed();
                fileDecryptionTime = decryptM.getTimeDifference();


                alertInfo.setHeaderText("File Decrypted Successfully");
                StringBuilder alertMessage = new StringBuilder();


                if(!decryptionMeasurementType.equalsIgnoreCase("DecryptFileOnly")){
                    alertMessage.append("Decryption + Signature Verification Time: " + convertedNanoSecondToSecondTime(fileDecryptionTime + fileDecryptionSignatureVerificationTime) + " Seconds");
//                    alertMessage.append("\nDecryption + Signature Verification Memory Used: " + convertedBytesToMb(fileDecryptionMemoryUsage + fileDecryptionSignatureVerificationMemoryUsage) + " MB");
                }else{
                    alertMessage.append("Decryption Time: " + convertedNanoSecondToSecondTime(fileDecryptionTime) +
                            "Seconds");
//                    alertMessage.append("\nDecryption Memory Used: " + convertedBytesToMb(fileDecryptionMemoryUsage) + "MB");
                }

                alertInfo.setContentText(alertMessage.toString());
                alertInfo.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
                alertInfo.showAndWait();

                return;
            } catch (Exception ex) {
                LOGGER.error(null, ex);
            }
        });

        btnClearEncrypt.setOnAction(event -> {
            textFieldEncryptedFileDestination.setText("");
            textFieldFileToEncrypt.setText("");
            textFieldEncryptionInitVector.setText("");
            textFieldEncryptionSecretKey.setText("");
            textFieldEncryptionEncryptedSecretKey.setText("");
            textFieldEncryptionHash.setText("");
            textFieldEncryptionDigitalSignature.setText("");
            buttonEncryptFileTrigger.setDisable(true);
            btnClearDecrypt.fire();
        });

        btnClearDecrypt.setOnAction(event -> {
            textFieldDecryptionInitVector.setText("");
            textFieldEncryptedFileToDecrypt.setText("");
            textFieldDecryptedFileDestination.setText("");
            textFieldDecryptionHash.setText("");
            textFieldDecryptedDigitalSignature.setText("");
        });
    }

    private void setupBrowseFileToEncryptHandler() {
        buttonBrowseFileToEncrypt.setOnAction(event -> {
            Stage stage = new Stage();
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Select File To Encrypt");

            File file = fileChooser.showOpenDialog(stage);

            PerformantMetricsApp.setDialogIcon(alertInfo);
            if (file == null) {
                alertInfo.setContentText("Please You Have To Select A Valid File For Encryption");
                alertInfo.show();
                textFieldFileToEncrypt.setText(null);
                return;
            }else{
                this.selectedFile = file;
                textFieldFileToEncrypt.setText(selectedFile.getAbsolutePath());
                this.selectedEncryptedFileDestination = new File(selectedFile.getAbsolutePath() + ".ENCRYPTED");
//                textFieldEncryptedFileToDecrypt.setText(selectedFile.getAbsolutePath() + ".ENCRYPTED");
                textFieldEncryptedFileDestination.setText(selectedFile.getAbsolutePath() + ".ENCRYPTED");
                alertInfo.setHeaderText("Destination Of Encrypted File Is SET for you Automatically");
                alertInfo.setContentText("If Not OKay with it please Change it" );
                alertInfo.show();
            }

        });


    }


    private void setupBrowseFileToDecryptHandler() {

        buttonBrowseEncryptedFileToDecrypt.setOnAction( event -> {

            if(browseFileToDecryptStage == null) {
                browseFileToDecryptStage = new Stage();
            }

            if(fileChooserDecrypt == null) {
                fileChooserDecrypt = new FileChooser();
            }

//            fileChooserDecrypt.setSelectedExtensionFilter(selectedExtensionFilter);

            fileChooserDecrypt.setTitle("Select File To Decrypt");
            fileChooserDecrypt.setSelectedExtensionFilter(new FileChooser.ExtensionFilter(
                    "Encrypted File", "ENCRYPTED"));

            File file = fileChooserDecrypt.showOpenDialog(browseFileToDecryptStage);
            if (file == null) {
                alertInfo.setContentText("Please You Have To Select A Valid File For Decryption");
                alertInfo.show();
                textFieldEncryptedFileToDecrypt.setText(null);
                return;
            }else{
                String path = file.getAbsolutePath();
                String newPath = "";
                try {
                    newPath = getNewTargetDecryptionPath(path);
                }catch(Exception e){
                    alertInfo.setContentText(e.getMessage());
                    alertInfo.showAndWait();
                    return;
                }
                textFieldEncryptedFileToDecrypt.setText(path);

                this.textFieldDecryptedFileDestination.setText(newPath);

                alertInfo.setHeaderText("Destination Of Decrypted File Is SET for you Automatically");
                alertInfo.setContentText("If Not OKay with it please Change it" );
                alertInfo.getDialogPane().setPrefHeight(Region.USE_PREF_SIZE);
                alertInfo.show();
            }
        });
    }

    public static void main(String[] args) {
        String str = "C:\\Users\byteworks\\Documents\\LittleBookofQuotes.pdf.ENCRYPTED";
        System.out.println("HIHI: " + getNewTargetDecryptionPath(str) );
    }

    public static String getNewTargetDecryptionPath(String path){
        String[] pathArray = path.split("\\.");

        String errorMsg = "Please Select a Valid Encrypted File with 'ENCRYPTED' Extension";

        if(pathArray.length < 2){
            throw new IllegalArgumentException(errorMsg);
        }

        System.out.println(Arrays.toString(pathArray));
        System.out.println("Arrays.toString(pathArray): " + pathArray[pathArray.length - 1]);

        if(!(pathArray[pathArray.length - 1]).equals("ENCRYPTED")){
            throw new IllegalArgumentException(errorMsg);
        }

        String pdfExt = pathArray[pathArray.length - 2];

        String newPath = path.replace("." + pdfExt +"." + pathArray[pathArray.length - 1], "");
        int randNum = new Random().nextInt();
        if(randNum < 0){
            randNum = randNum * -1;
        }

        String outcome = newPath + "-" + randNum + "-Decrypted." + pdfExt;

        return outcome;
    }

    private void setupEncryptFileTriggerHandler() {

        PerformantMetricsApp.setDialogIcon(alertInfo);
        buttonEncryptFileTrigger.setOnAction(event -> {

            if(this.aesEncyrpt == null){
                alertInfo.setContentText("Please Generate Private/Public Key Before Proceeding");
                alertInfo.show();
                return;
            }

            if(this.selectedFile == null){
                alertInfo.setContentText("Please Select File To Encrypt");
                alertInfo.show();
                return;
            }

            if( this.selectedEncryptedFileDestination == null ){
                alertInfo.setContentText("Please Destination Of Encrypted File");
                alertInfo.show();
                return;
            }

            MetricsMeasurement encryptMeasurement = MetricsMeasurement.startMM();
            this.performAESEncryptionOfFile();
            encryptMeasurement.stop();
            fileEncryptionMemoryUsage = encryptMeasurement.getMemoryUsed();
            fileEncryptionTime = encryptMeasurement.getTimeDifference();

            StringBuilder alertMessage = new StringBuilder();


            if(!encryptionMeasurementType.equalsIgnoreCase("EncryptFileOnly")){
                alertMessage.append("Encryption + Signature Generation Time: " + convertedNanoSecondToSecondTime(fileEncryptionTime + fileEncryptionSignatureVerificationTime)  + " Seconds");
//                alertMessage.append("\nEncryption + Signature Generation Memory Used: " + convertedBytesToMb(fileEncryptionMemoryUsage + fileEncryptionSignatureVerificationMemoryUsage) + " MB");
            }else{
                alertMessage.append("Encryption Time: " + convertedNanoSecondToSecondTime(fileEncryptionTime) + " " +
                        "Seconds");
//                alertMessage.append("\nEncryption Memory Used: " + convertedNanoSecondToSecondTime(fileEncryptionMemoryUsage) + " MB");
            }

            alertInfo.setContentText(alertMessage.toString());
            alertInfo.show();

        });
    }

    public static double convertedNanoSecondToSecondTime(long time){
        return  (double)time/1000000000;
    }

    public static double convertedBytesToMb(long bytesdata){
        return  (double)bytesdata/(1024 * 1024);
    }

    private void setupGenerateKeyHandler() {
        buttonGenerateKeyPairAndSecretKey.setOnAction(event -> {
            RSAKeyPairGenerator rsaKeyPairGen;

            try {
                rsaKeyPairGen = new RSAKeyPairGenerator();

                rsaKeyPairGen.generateNewKeyPair();
                rsaKeyPairGen.writePublicAndPrivateKeyToFile("_USER_A");
                rsaKeyPairGen.generateNewKeyPair();
                rsaKeyPairGen.writePublicAndPrivateKeyToFile("_USER_B");

                rsaKeyPairGen.readPublicAndPrivateKeyFromFile("_USER_A");
                rsaKeyPairGen.readPublicAndPrivateKeyFromFile("_USER_B");

                tmpRSAPrivateKey_A = rsaKeyPairGen.getPrivateKeys().get("_USER_A");
                tmpRSAPublicKey_A = rsaKeyPairGen.getPublicKeys().get("_USER_A");

                tmpRSAPrivateKey_B = rsaKeyPairGen.getPrivateKeys().get("_USER_B");
                tmpRSAPublicKey_B = rsaKeyPairGen.getPublicKeys().get("_USER_B");

                processEccKeyPairActivation();

                MetricsMeasurement signatureMetrics = MetricsMeasurement.startMM();

                aesEncyrpt = new AesEncyrpt("256");

                textFieldEncryptionSecretKey.setText(aesEncyrpt.getKey());
                hiddenTextFieldIV.setText(aesEncyrpt.getInitVector());
                textFieldDecryptionInitVector.setText(aesEncyrpt.getInitVector());
                textFieldEncryptionInitVector.setText(aesEncyrpt.getInitVector());


                System.out.println("AesEncyrpt: " + aesEncyrpt.getKey());
                System.out.println("Init Vector: " + aesEncyrpt.getInitVector());

                this.performEncryptionOfAESSecretKeyWithRSA(aesEncyrpt.getKey(), tmpRSAPublicKey_B);

                String myChecksum = hashSecretKey();

                textFieldEncryptionHash.setText(myChecksum);
                textFieldDecryptionHash.setText(myChecksum);


                String signECDSA = ECDSAHelper.signECDSA(privateKeyAEcc, myChecksum);
                textFieldEncryptionDigitalSignature.setText(signECDSA);
                textFieldDecryptedDigitalSignature.setText(signECDSA);

                signatureMetrics.stop();

                fileEncryptionSignatureVerificationTime = signatureMetrics.getTimeDifference();
                fileEncryptionSignatureVerificationMemoryUsage = signatureMetrics.getMemoryUsed();

                buttonEncryptFileTrigger.setDisable(false);

            } catch (NoSuchAlgorithmException ex) {
                LOGGER.error(null, ex);
            } catch (Exception ex) {
                LOGGER.error(null, ex);
            }

        });
    }

    private void setUpMeasurementTypeHandler() {
        handleEncryptionMeasurement();
        handleDecryptionMeasurement();
    }

    private void handleDecryptionMeasurement() {
        decryptionMeasurementType = "DecryptFileOnly";
        decryptToggleOption = new ToggleGroup();
        radioButtonDecryptFileDecryptOnly.setUserData("DecryptFileOnly");
        radioButtonDecryptFileDecryptOnly.setToggleGroup(decryptToggleOption);
        radioButtonDecryptFileDecryptOnly.setSelected(true);

        radioButtonDecryptFileDecryptWithSignatureVerification.setUserData("DecryptWithSignatureVerification");
        radioButtonDecryptFileDecryptWithSignatureVerification.setToggleGroup(decryptToggleOption);

        decryptToggleOption.selectedToggleProperty().addListener(new ChangeListener<Toggle>() {
            @Override
            public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue, Toggle newValue) {
                if (decryptToggleOption.getSelectedToggle() != null) {
                    decryptionMeasurementType = (String) newValue.getUserData();
                    if (decryptToggleOption.getSelectedToggle().getUserData().equals("DecryptFileOnly")) {
                    }
                    if (decryptToggleOption.getSelectedToggle().getUserData().equals(
                            "DecryptWithSignatureVerification")) {
                    }
                }
            }
        });

    }

    private void handleEncryptionMeasurement() {

        encryptionMeasurementType = "EncryptFileOnly";
        encryptToggleOption = new ToggleGroup();
        radioButtonEncryptFileEncryptOnly.setUserData("EncryptFileOnly");
        radioButtonEncryptFileEncryptOnly.setToggleGroup(encryptToggleOption);
        radioButtonEncryptFileEncryptOnly.setSelected(true);

        radioButtonEncryptFileEncryptWithSignatureVerification.setUserData("EncryptWithSignatureVerification");
        radioButtonEncryptFileEncryptWithSignatureVerification.setToggleGroup(encryptToggleOption);

        encryptToggleOption.selectedToggleProperty().addListener(new ChangeListener<Toggle>() {
            @Override
            public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue, Toggle newValue) {

                System.out.println("Measurement Type Changing: " + oldValue.getUserData() + " newVal: " + newValue.getUserData());

                if (encryptToggleOption.getSelectedToggle() != null) {
                    encryptionMeasurementType = (String) newValue.getUserData();
                    System.out.println("encryptionMeasurementType: " + encryptionMeasurementType);
                    if (encryptToggleOption.getSelectedToggle().getUserData().equals("EncryptFileOnly")) {
                    }
                    if (encryptToggleOption.getSelectedToggle().getUserData().equals(
                            "DecryptWithSignatureVerification")) {
                    }
                }
            }
        });
    }

    public static void processEccKeyPairActivation() throws Exception {

        keyPairAEcc = ECDSAHelper.getKeyPair();
        keyPairBEcc = ECDSAHelper.getKeyPair();

        publicKeyAEcc = keyPairAEcc.getPublic();
        privateKeyAEcc = keyPairAEcc.getPrivate();

        publicKeyBEcc = keyPairBEcc.getPublic();
        privateKeyBEcc = keyPairBEcc.getPrivate();

//        if(publicKeyAEcc == null){
//            System.out.println("publicKeyAEcc is NULL");
//        }
//        if(publicKeyBEcc == null){
//            System.out.println("publicKeyBEcc is NULL");  
//        }


        //Key to hexadecimal string
        String publicKeyAString = HexUtil.encodeHexString(publicKeyAEcc.getEncoded());
        String privateKeyAString = HexUtil.encodeHexString(privateKeyAEcc.getEncoded());
        System.out.println("Generate public key:(A) " + publicKeyAString );
        System.out.println("Generate private key:(A) " + privateKeyAString );


        String publicKeyBString = HexUtil.encodeHexString(publicKeyBEcc.getEncoded());
        String privateKeyBString = HexUtil.encodeHexString(privateKeyBEcc.getEncoded());
        System.out.println("Generate public key:(B) " + publicKeyBString );
        System.out.println("Generate private key:(B)(9090909) " + privateKeyBString );


        //Hexadecimal string to key object
        privateKeyAEcc = ECDSAHelper.getPrivateKey(privateKeyAString);
        publicKeyAEcc = ECDSAHelper.getPublicKey(publicKeyAString);

        privateKeyBEcc = ECDSAHelper.getPrivateKey(privateKeyBString);
        publicKeyBEcc = ECDSAHelper.getPublicKey(publicKeyBString);

        String retrievedPublicKey = HexUtil.encodeHexString(publicKeyAEcc.getEncoded());
        String retrievedPrivateKey = HexUtil.encodeHexString(privateKeyAEcc.getEncoded());


        String retrievedPublicKeyB = HexUtil.encodeHexString(publicKeyBEcc.getEncoded());
        String retrievedPrivateKeyB = HexUtil.encodeHexString(privateKeyBEcc.getEncoded());

        System.out.println("Retrieved public key (A): " + retrievedPublicKey);
        System.out.println("Retrieved private key (A): " + retrievedPrivateKey);


        System.out.println("Retrieved public key (B): " + retrievedPublicKeyB);
        System.out.println("Retrieved private key (B): " + retrievedPrivateKeyB);

    }

    private static PrivateKey privateKeyBEcc;
    private static PublicKey publicKeyBEcc;
    private static PrivateKey privateKeyAEcc;
    private static PublicKey publicKeyAEcc;
    private static KeyPair keyPairBEcc;
    private static KeyPair keyPairAEcc;

    enum HashType {
        MD5, SHA2, BLAKE2, BLAKE3
    }

    private void performEncryptionOfAESSecretKeyWithRSA(String secStringKey, Key userEncrypKey) throws Exception{
        System.out.println("BEFORE_ENCRYPTION: " + secStringKey);

        MetricsMeasurement ms = MetricsMeasurement.startMM();

        byte[] encData = AesEncryptionHelper.encryptSKey(secStringKey, userEncrypKey );

        AesEncryptionHelper.writeByte(encData, EncryptKeyPairGenerator.secretKeyPath + ".skey-enc");
        String encryptedStringAES = new String(encData);

//        byte[] encDataFromFile = readByteFromFile(EncryptKeyPairGenerator.secretKeyPath + ".skey-enc");

        System.out.println("ENCRYPTED-STRING-1: " + encryptedStringAES);

//        this.jTextFieldEncryptedSecretKey.setText(encryptedStringAES); //TODO: remove

        this.textFieldEncryptionEncryptedSecretKey.setText(encryptedStringAES);
//        this.jTextFieldSecretKeyEncrypted2.setText(encryptedStringAES);

        ms.stop();
        System.out.println("Encryption-Time-Diff: " + ms.getTimeDifference());

//        System.out.println("ENCRYPTED-STRING: " + new String(encDataFromFile));

//        if(userDecryptKey != null){
//
//        String decrpDataStr = decryptEncrptedSKey(encData, userDecryptKey);
//
////        String decrpDataFromFileStr = decryptEncrptedSKey(encDataFromFile, userDecryptKey);
//
//
//        System.out.println("DECRYPTED STRING: " + decrpDataStr);
//
////        System.out.println("DECRYPTED STRING-FROM FILE: " + decrpDataFromFileStr);
//        }
//
//        aesEncyrpt.rsaDecryptSecretKey(userAPublicKey, EncryptKeyPairGenerator.secretKeyPath);
//        aesEncyrpt.decryptEncrptedSKey(userAPublicKey, EncryptKeyPairGenerator.secretKeyPath);


    }

    private String hashSecretKey() throws Exception{

        MessageDigest md = MessageDigest.getInstance("sha-256");
        md.update(Files.readAllBytes(Paths.get(EncryptKeyPairGenerator.secretKeyPath + ".skey-enc")));
//        md.update(Files.readAllBytes(Paths.get(toBeEncryptedOutputFilePath)));
        byte[] digest = md.digest();

        String myChecksum = DatatypeConverter
                .printHexBinary(digest).toUpperCase();
        System.out.println("sha-256-Digest: " + myChecksum);

        return myChecksum;

    }

    private String performDecryptionOfAESSecretKeyWithRSA(Key userDecryptKey) throws Exception {
        System.out.println("DE_CRYPTION: " );

        if(!Files.exists(Paths.get(EncryptKeyPairGenerator.secretKeyPath + ".skey-enc"))){
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setContentText("No Data/File Found, Cant Decrypt");
            alert.showAndWait();
            return null;
        }

        byte[] encDataFromFile = AesEncryptionHelper.readByteFromFile(EncryptKeyPairGenerator.secretKeyPath + ".skey-enc");

        String encDataFromFileString = new String(encDataFromFile);

        System.out.println("ENCRYPTED-STRING-FROM-FILE-1: " + encDataFromFileString);
//        this.jTextFieldEncryptedSecretKey.setText(encDataFromFileString);
//        System.out.println("ENCRYPTED-STRING: " + new String(encDataFromFile));

        if (userDecryptKey != null) {

            String decrpDataStr = AesEncryptionHelper.decryptEncrptedSKey(encDataFromFile, userDecryptKey);

//        String decrpDataFromFileStr = decryptEncrptedSKey(encDataFromFile, userDecryptKey);
            System.out.println("DECRYPTED STRING: " + decrpDataStr);

            return decrpDataStr;

//        System.out.println("DECRYPTED STRING-FROM FILE: " + decrpDataFromFileStr);
        }

        return null;

//        aesEncyrpt.rsaDecryptSecretKey(userAPublicKey, EncryptKeyPairGenerator.secretKeyPath);
//        aesEncyrpt.decryptEncrptedSKey(userAPublicKey, EncryptKeyPairGenerator.secretKeyPath);


//
//        MessageDigest md = MessageDigest.getInstance("sha-256");
//        md.update(Files.readAllBytes(Paths.get(EncryptKeyPairGenerator.secretKeyPath + ".skey-enc")));
////        md.update(Files.readAllBytes(Paths.get(toBeEncryptedOutputFilePath)));
//        byte[] digest = md.digest();
//
//        String myChecksum = DatatypeConverter
//                .printHexBinary(digest).toUpperCase();
//        System.out.println("sha-256-Digest: " + myChecksum);
//
//        jTextField3EncryptedFileHash.setText(myChecksum);

    }

    private void performAESEncryptionOfFile() {

        Alert alert = new Alert(Alert.AlertType.INFORMATION);

        try {

//            this.jTextFieldSymmetricKey.setText(aesEncyrpt.getKey());
//            this.jTextFieldDecryptedSymmetricKey.setText(aesEncyrpt.getKey());

//            aesEncyrpt.verifyAesKey(Integer.parseInt(this.selectedAesBitSize), this.jTextFieldSymmetricKey.getText().toString());

            long startTime = System.nanoTime();
            final String selectedEncryptedFileDestinationAbsolutePath = this.selectedEncryptedFileDestination.getAbsolutePath();
            aesEncyrpt.encryptFile(this.selectedFile.getAbsolutePath(), selectedEncryptedFileDestinationAbsolutePath);

            System.out.println("SECRET-KEY: " + aesEncyrpt.getKey());
            System.out.println("Init Vector: " + aesEncyrpt.getInitVector());
            this.textFieldEncryptedFileToDecrypt.setText(selectedEncryptedFileDestinationAbsolutePath);
            String newPath = getNewTargetDecryptionPath(selectedEncryptedFileDestinationAbsolutePath);
            this.textFieldDecryptedFileDestination.setText(newPath);

//            this.messageDigest = this.hashEncyptedFileWith(this.selectedEncryptedFileDestination);
            long endTime = System.nanoTime();

//            JOptionPane.showMessageDialog(this, "File Encrypted And Hashed Successfully, See Hash Updated TextBox", "Success Message", JOptionPane.INFORMATION_MESSAGE);
//            JOptionPane.showMessageDialog(this, , JOptionPane.INFORMATION_MESSAGE);


            alert.setTitle("Success Message");
            alert.setContentText("Encryption Time: " + (endTime - startTime));
        } catch (IllegalArgumentException iae) {
            alert.setAlertType(Alert.AlertType.ERROR);
            alert.setContentText(iae.getMessage());
            alert.show();
        }


    }

    //using MD5 Message Digest Algorithm
    private String hashEncyptedFileWith(File encryptedFilePath) {
        String messageDigest = "";
        try{
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(Files.readAllBytes(Paths.get(encryptedFilePath.getAbsolutePath())));
            byte[] digest = md.digest();
            String myChecksum = DatatypeConverter
                    .printHexBinary(digest).toUpperCase();
            messageDigest = myChecksum;
        }catch(IOException | NoSuchAlgorithmException ex){
            ex.printStackTrace();
        }
        System.out.println( "Encrypted File: MD5-Digest: " + messageDigest );
//        this.jTextField3EncryptedFileHash.setText(messageDigest);
//        this.jTextField5EncryptedFileHashTBForFile.setText(messageDigest);
        return messageDigest;
    }

}

