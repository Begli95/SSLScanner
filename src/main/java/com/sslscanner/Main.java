package com.sslscanner;

import com.sslscanner.controllers.HomeController;
import com.sslscanner.controllers.ScanController;
import io.javalin.Javalin;


public class Main {
    public static void main(String[] args) {
        Javalin app = Javalin.create().start(7070);
        // Обработчик маршрута для корневого пути
        addRoutes(app);
    }

    private static void addRoutes(Javalin app) {
        app.get("/", HomeController.homeHandler);
        app.post("/scan", ScanController.scanHandler);
    }
}