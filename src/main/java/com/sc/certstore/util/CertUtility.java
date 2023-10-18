package com.sc.certstore.util;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

public class CertUtility {

    public static RestTemplate restTemplateWithMTLS(String keystorePath, String keystorePassword,
                                                    String truststorePath, String truststorePassword) throws Exception {
        // Load the keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream instream = new FileInputStream(new File(keystorePath))) {
            keyStore.load(instream, keystorePassword.toCharArray());
        }

        // Load the truststore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream instream = new FileInputStream(new File(truststorePath))) {
            trustStore.load(instream, truststorePassword.toCharArray());
        }

        // Build an SSL context with the keystore and truststore
        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(keyStore, keystorePassword.toCharArray())
                .loadTrustMaterial(trustStore, new TrustSelfSignedStrategy())
                .build();

        CloseableHttpClient httpClient = HttpClients.custom()
                .setSslcontext(sslContext)
                .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();

        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return new RestTemplate(factory);
    }

}
