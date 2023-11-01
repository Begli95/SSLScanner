package com.sslscanner;

import com.sslscanner.controllers.HomePageController;
import com.sslscanner.controllers.ScanController;
import io.javalin.Javalin;


public class Main {
    public static void main(String[] args) {
        Javalin app = Javalin.create().start(7070);
        addRoutes(app);
    }

    private static void addRoutes(Javalin app) {
        app.get("/", HomePageController.homeHandler);
        app.post("/scan", ScanController.scanHandler);
    }
}