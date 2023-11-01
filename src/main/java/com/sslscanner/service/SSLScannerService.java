package com.sslscanner.service;

import org.apache.http.ParseException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.DateUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.protocol.BasicHttpContext;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class SSLScannerService implements Runnable {
    private final String ipRange;
    private final CloseableHttpClient sharedHttpClient;

    public SSLScannerService(String ipRange, CloseableHttpClient sharedHttpClient) {
        this.ipRange = ipRange;
        this.sharedHttpClient = sharedHttpClient;
    }

    public void scan() throws IOException, ParseException {
        final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
        final String PEER_DOMAIN = "PEER_DOMAIN";

        String[] ip = ipRange.split("-");
        String startIP = ip[0].trim();
        String endIP = ip[1].trim();


        try {
            InetAddress startAddress = InetAddress.getByName(startIP);
            InetAddress endAddress = InetAddress.getByName(endIP);


            while (!startAddress.equals(endAddress)) {

                String ipAddress = startAddress.getHostAddress();
                System.out.println(ipAddress);


                if (isLocalAddress(ipAddress)) {
                    System.out.println("Skipping local address: " + ipAddress);
                }else {


                    try (CloseableHttpClient httpClient = sharedHttpClient) {
                        HttpGet httpget = new HttpGet("https://" + ipAddress);
                        System.out.println("Executing request " + httpget.getRequestLine());

                        BasicHttpContext context = new BasicHttpContext();

                        try {
                            httpClient.execute(httpget, context);
                        } catch (IOException e) {
                            System.out.println("No SSL certificate found for domain: " + ipAddress);
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
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    private boolean isLocalAddress(String address) {
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
