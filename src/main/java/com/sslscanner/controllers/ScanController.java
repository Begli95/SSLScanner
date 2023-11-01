package com.sslscanner.controllers;

import com.sslscanner.service.IpRangeSplitterService;
import com.sslscanner.service.SSLScannerService;
import io.javalin.http.Handler;

import java.util.List;
import java.util.Objects;

public class ScanController {
    public static Handler scanHandler = ctx -> {

        String ipRange = ctx.formParam("ipRange");
        int numThreads = Integer.parseInt(Objects.requireNonNull(ctx.formParam("numThreads")));

        IpRangeSplitterService.execute(ipRange, numThreads);

        ctx.result("Scanning in progress. Check the results later.");
    };
}
