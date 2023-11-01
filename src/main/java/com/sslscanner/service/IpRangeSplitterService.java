package com.sslscanner.service;

import org.apache.http.HttpResponseInterceptor;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpCoreContext;

import javax.net.ssl.SSLSession;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class IpRangeSplitterService {
    public static List<String> splitIPRange(String startIP, int mask, int numThreads) {
        List<String> ipRanges = new ArrayList<>();
        try {
            InetAddress inetStartIP = Inet4Address.getByName(startIP);
            long start = ipToLong(inetStartIP);
            long totalIPs = (1L << (32 - mask));
            long ipsPerThread = totalIPs / numThreads;

            for (int i = 0; i < numThreads; i++) {
                long threadStart = start + i * ipsPerThread;
                long threadEnd = threadStart + ipsPerThread - 1;
                InetAddress inetThreadStart = longToIP(threadStart);
                InetAddress inetThreadEnd = longToIP(threadEnd);
                String range = inetThreadStart.getHostAddress() + "-" + inetThreadEnd.getHostAddress();
                System.out.println("ip "+range);
                ipRanges.add(range);
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return ipRanges;
    }

    private static long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }

    private static InetAddress longToIP(long ip) {
        byte[] octets = new byte[4];
        for (int i = 0; i < 4; i++) {
            octets[3 - i] = (byte) ((ip >> (i * 8)) & 0xFF);
        }
        try {
            return InetAddress.getByAddress(octets);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void execute(String ipRange, int numThreads){
        final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
        final String PEER_DOMAIN = "PEER_DOMAIN";

        String[] ipAndMask = ipRange.split("/");

        String ipAddress = ipAndMask[0].trim();
        int mask = Integer.parseInt(ipAndMask[1].trim());

        List<String> ipRanges = splitIPRange(ipAddress, mask, numThreads);

        ExecutorService executorService = Executors.newFixedThreadPool(numThreads);

        HttpResponseInterceptor certificateInterceptor = (httpResponse, context) -> {
            ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection) context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
            SSLSession sslSession = routedConnection.getSSLSession();
            if (sslSession != null) {
                Certificate[] certificates = sslSession.getPeerCertificates();
                context.setAttribute(PEER_CERTIFICATES, certificates);
            } else {
                context.setAttribute(PEER_DOMAIN, ipAddress);
            }
        };

        CloseableHttpClient sharedHttpClient = HttpClients
                .custom()
                .addInterceptorLast(certificateInterceptor)
                .build();

        for (String ip : ipRanges) {
            executorService.execute(() -> {
                try {
                    SSLScannerJob sslScanner = new SSLScannerJob(ipRange, sharedHttpClient);
                    sslScanner.run();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        executorService.shutdown();
    }
}
