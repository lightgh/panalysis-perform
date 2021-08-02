package com.samson;

import javafx.scene.image.Image;

/**
 * @author - Chinaka .I. Light <ichinaka@byteworks.com.ng>
 * Date: 21/07/2021
 */
public class Constants {
    public static final String MAIN_VIEW = "com/samson/MainView.fxml";
    public static final String LOGIN_VIEW = "com/samson/LoginView.fxml";

    public static final String FAVICON_IMAGE_PATH = "com/samson/1163519.png";

    public static final Image APP_IMAGE_ICON  =
            new Image(Constants.class.getClassLoader().getResource(FAVICON_IMAGE_PATH).toString());
}
