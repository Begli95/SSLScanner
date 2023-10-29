package com.sslscanner.controllers;

import com.sslscanner.service.SSLScannerService;
import io.javalin.http.Handler;
import java.util.Objects;

public class ScanController {
    public static Handler scanHandler = ctx -> {
        // Получите значения из формы
        String ipRange = ctx.formParam("ipRange");
        int numThreads = Integer.parseInt(Objects.requireNonNull(ctx.formParam("numThreads")));

        // Вызов службы для выполнения сканирования
        SSLScannerService.scan(ipRange, numThreads);

        // Отправка сообщения об успешном сканировании
        ctx.result("Scanning in progress. Check the results later.");
    };
}
