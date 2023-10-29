package com.sslscanner.service;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.ParseException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

public class SSLScannerService {
    public static void scan(String ipRange, int threads) throws  IOException, ParseException {

        String[] ipAndMask = ipRange.split("/");
//        String ipAddress = ipAndMask[0].trim();
        String ipAddress = "8.8.8.8";
        int mask = Integer.parseInt(ipAndMask[1].trim());
        System.out.println(ipAddress);
        // Определение диапазона IP-адресов с битовым сдвигом
        int numAddresses = 1 << (32 - mask);

        try {
            Security.addProvider(new BouncyCastleProvider());


            // Создаем HTTP-клиент
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet("https://" + ipAddress);
            System.out.println(httpGet);
            // Отправляем GET-запрос
            CloseableHttpResponse response = httpClient.execute(httpGet);
            System.out.println("1");
            // Извлекаем SSL-сертификат из ответа
            InputStream certInputStream = response.getEntity().getContent();
            System.out.println("2");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            System.out.println("3");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certInputStream);

            // Извлекаем домены из сертификата
            Collection<?> subjectAlternativeNames = certificate.getSubjectAlternativeNames();
            if (subjectAlternativeNames != null) {
                for (Object san : subjectAlternativeNames) {
                    System.out.println("Домен: " + san);
                }
            }
            // Закрываем HTTP-клиент
            httpClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
