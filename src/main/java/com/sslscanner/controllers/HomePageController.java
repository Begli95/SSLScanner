package com.sslscanner.controllers;

import io.javalin.http.Handler;

public class HomePageController {
    public static Handler homeHandler = ctx -> {
        // Отображение основной страницы ввода параметров сканирования
        ctx.render("templates/index.html");
    };
}
