package com.sslscanner.service;

import org.apache.http.HttpResponseInterceptor;
import org.apache.http.ParseException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.DateUtils;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpCoreContext;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class SSLScannerService implements Runnable{
    private final String ipRange;
    private final int threadNumber;
    public SSLScannerService(String ipRange, int threadNumber) {
        this.ipRange = ipRange;
        this.threadNumber = threadNumber;
    }
    public void scan() throws  IOException, ParseException {

//        String[] ipAndMask = ipRange.split("/");
//        String ipAddress = ipAndMask[0].trim();
//        String ipAddress = "8.8.4.4";
//        int mask = Integer.parseInt(ipAndMask[1].trim());

//        int numAddresses = 1 << (32 - mask);

        String[] ip = ipRange.split("-");
        String startIP = ip[0].trim();
        String endIP = ip[1].trim();


        try {
            InetAddress startAddress = InetAddress.getByName(startIP);
            InetAddress endAddress = InetAddress.getByName(endIP);

            while (!startAddress.equals(endAddress)) {
//                System.out.println(startAddress.getHostAddress()+" Работает поток "+thred);
                String ipAddress = startAddress.toString();
                System.out.println(ipAddress);
                final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
                final String PEER_DOMAIN = "PEER_DOMAIN";

                //проверка является ли ip адрес локальным или недоступным
                if (isLocalAddress(ipAddress)) {
                    System.out.println("Skipping local address: " + ipAddress);
                    return;
                }

                HttpResponseInterceptor certificateInterceptor = (httpResponse, context) -> {
                    ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection)context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
                    SSLSession sslSession = routedConnection.getSSLSession();
                    if (sslSession != null) {
                        Certificate[] certificates = sslSession.getPeerCertificates();
                        context.setAttribute(PEER_CERTIFICATES, certificates);
                    }else {
                        context.setAttribute(PEER_DOMAIN, ipAddress);
                    }
                };

                try (CloseableHttpClient httpClient = HttpClients
                        .custom()
                        .addInterceptorLast(certificateInterceptor)
                        .build()) {
                    HttpGet httpget = new HttpGet("https://" + ipAddress);
                    System.out.println("Executing request " + httpget.getRequestLine());

                    BasicHttpContext context = new BasicHttpContext();

                    try {
                        httpClient.execute(httpget, context);
                    } catch (IOException e) {
                        System.out.println("No SSL certificate found for domain: " + ipAddress);
                        return; // Пропустить сайт без SSL-сертификата
                    }

                    Certificate[] peerCertificates = (Certificate[]) context.getAttribute(PEER_CERTIFICATES);
                    String peerDomain = (String) context.getAttribute(PEER_DOMAIN);
                    if (peerCertificates != null) {
                        for (Certificate certificate : peerCertificates) {
                            X509Certificate real = (X509Certificate) certificate;
                            System.out.println("----------------------------------------");
                            System.out.println("Type: " + real.getType());
                            System.out.println("Signing Algorithm: " + real.getSigAlgName());
                            System.out.println("IssuerDN Principal: " + real.getIssuerX500Principal());
                            System.out.println("SubjectDN Principal: " + real.getSubjectX500Principal());
                            System.out.println("Not After: " + DateUtils.formatDate(real.getNotAfter(), "dd-MM-yyyy"));
                            System.out.println("Not Before: " + DateUtils.formatDate(real.getNotBefore(), "dd-MM-yyyy"));
                        }
                    } else {
                        if (peerDomain != null) {
                            System.out.println("No SSL certificate found for domain: " + peerDomain);
                        } else {
                            System.out.println("No SSL certificate or domain found.");
                        }
                    }
                }


                byte[] addressBytes = startAddress.getAddress();
                int i = addressBytes.length - 1;
                while (i >= 0 && addressBytes[i] == (byte) 255) {
                    addressBytes[i] = 0;
                    i--;
                }

                if (i >= 0) {
                    addressBytes[i]++;
                }

                startAddress = InetAddress.getByAddress(addressBytes);

                System.out.println(ipAddress);

            }
            // Выводим последний адрес
//            System.out.println(endAddress.getHostAddress()+" Работает поток "+thred);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }


    }
    private static boolean isLocalAddress(String address) {
        try {
            InetAddress inetAddress = InetAddress.getByName(address);
            return inetAddress.isSiteLocalAddress() || inetAddress.isLinkLocalAddress();
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public void run() {
        try {
            scan();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
