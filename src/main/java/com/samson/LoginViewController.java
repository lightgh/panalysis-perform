package com.samson;

/**
 * @author - Chinaka .I. Light <ichinaka@byteworks.com.ng>
 * Date: 26/07/2021
 */

import java.io.IOException;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;

import static com.samson.PerformantMetricsApp.primaryStage;

public class LoginViewController {

    @FXML
    private ResourceBundle resources;

    @FXML
    private URL location;

    @FXML
    private TextField userNameTextField;

    @FXML
    private PasswordField passwordField;

    @FXML
    private Button signInButton;

    @FXML
    private ProgressIndicator progressBarSignIn;

    @FXML
    void handleOnKeyReleased(KeyEvent event) {
        if (event.getCode().equals(KeyCode.ENTER)) {
            this.signInButton.fire();
        }
    }


    @FXML
    void handleSignInAction(ActionEvent event) throws IOException {
        if("password".equals(passwordField.getText()) && "admin".equals(userNameTextField.getText())){
            PerformantMetricsApp.mainLoginStage.hide();
            PerformantMetricsApp.configurePrimaryStage(primaryStage);
            PerformantMetricsApp.loadMainMenu(primaryStage);
        }
    }

    @FXML
    void initialize() {
        assert userNameTextField != null : "fx:id=\"userNameTextField\" was not injected: check your FXML file 'LoginView.fxml'.";
        assert passwordField != null : "fx:id=\"passwordField\" was not injected: check your FXML file 'LoginView.fxml'.";
        assert signInButton != null : "fx:id=\"signInButton\" was not injected: check your FXML file 'LoginView.fxml'.";
        assert progressBarSignIn != null : "fx:id=\"progressBarSignIn\" was not injected: check your FXML file 'LoginView.fxml'.";

    }
}
