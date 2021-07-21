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

    @Override
    public void start(Stage primaryStage) throws Exception {
        System.out.println("Running Successfully...");
        primaryStage = primaryStage;
        configurePrimaryStage(primaryStage);
        this.loadMainMenu();
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


    private void loadMainMenu() throws IOException {

        FXMLLoader fxmlLoader1 = new FXMLLoader();
        Pane rootSplashPane = (Pane) fxmlLoader1.load(getClass().getClassLoader().getResource(Constants.MAIN_VIEW));

        fxmlLoader1.getController();

        Stage mainStage = new Stage();

//        mainStage.initStyle(StageStyle.UNDECORATED);
        mainStage.setResizable(false);
        mainStage.setMaximized(false);

        Scene scene = new Scene(rootSplashPane);
        mainStage.setScene(scene);
        mainStage.show();
    }


    private void configurePrimaryStage(Stage primaryStage) {
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
