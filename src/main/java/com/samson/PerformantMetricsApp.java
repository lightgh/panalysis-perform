package com.samson;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import java.io.IOException;

/**
 * @author - Chinaka .I. Light <ichinaka@byteworks.com.ng>
 * Date: 21/07/2021
 */
public class PerformantMetricsApp extends Application {

    private static final Logger LOGGER = Logger.getLogger(PerformantMetricsApp.class);

    public static Stage primaryStage;
    public static Stage mainLoginStage;

    @Override
    public void start(Stage primaryStage) throws Exception {
        System.out.println("Running Successfully...");
        primaryStage = primaryStage;
        configurePrimaryStage(primaryStage);
        loadLoginMenu();
    }

    @Override
    public void init() throws Exception {
        super.init();
        initializeApp();
    }

    private void initializeApp() {
        PropertyConfigurator.configure("log4j.properties");
    }


    @Override
    public void stop() throws Exception {
        super.stop();
    }

    public static void main(String[] args) {
        launch(args);
    }


    public static void loadMainMenu(Stage primaryStage) throws IOException {

        FXMLLoader fxmlLoader1 = new FXMLLoader();
        Pane rootSplashPane =
                (Pane) fxmlLoader1.load(PerformantMetricsApp.class.getClassLoader().getResource(Constants.MAIN_VIEW));

        fxmlLoader1.getController();


        if(primaryStage == null) {
            primaryStage = new Stage();
        }
        Stage mainStage = primaryStage;

        primaryStage.setResizable(false);
        primaryStage.setMaximized(false);

        Scene scene = new Scene(rootSplashPane);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void loadLoginMenu() throws IOException {

        FXMLLoader fxmlLoader1 = new FXMLLoader();
        Pane rootSplashPane =
                (Pane) fxmlLoader1.load(PerformantMetricsApp.class.getClassLoader().getResource(Constants.LOGIN_VIEW));

        fxmlLoader1.getController();

        if(mainLoginStage == null)
            mainLoginStage = new Stage();

        mainLoginStage.setResizable(false);
        mainLoginStage.setMaximized(false);

        Scene scene = new Scene(rootSplashPane);
        mainLoginStage.setScene(scene);
        mainLoginStage.show();
    }


    public static void configurePrimaryStage(Stage primaryStage) {

        if(primaryStage == null) {
            primaryStage = new Stage();
        }
        primaryStage.setResizable(false);
        primaryStage.setMaximized(false);
        primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
            @Override
            public void handle(WindowEvent e) {
                e.consume();
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION, "Are you sure you want to exit? ",
                        ButtonType.YES
                        , ButtonType.NO);
//                UserInterfaceUtility.setDialogIcon(alert);
                alert.showAndWait();
                if (alert.getResult() == ButtonType.YES) {
                    Platform.exit();
                    System.exit(0);
                }
            }
        });
    }


}
