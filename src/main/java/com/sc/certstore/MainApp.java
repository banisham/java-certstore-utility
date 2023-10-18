package com.sc.certstore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

@SpringBootApplication
@EnableConfigurationProperties
public class MainApp {

    private static final Logger LOGGER = LoggerFactory.getLogger(MainApp.class);

    @Value("${client.cert.path}")
    private String clientCertFilePath;

    @Value("${client.privatekey.path}")
    private String clientPrivateKeyFilePath;

    @Value("${keystore.path}")
    private String keystorePath;

    @Value("${keystore.password}")
    private String keystorePassword;

    @Value("${key.password}")
    private String keyPassword;

    @Value("${truststore.path}")
    private String truststorePath;

    @Value("${truststore.password}")
    private String truststorePassword;

    public static void main(String[] args) {
        SpringApplication.run(MainApp.class, args);
    }

    @PostConstruct
    public void init() {
        try {
            // 1. Load the private key and certificate
            String privateKeyContent = new String(Files.readAllBytes(Paths.get(clientPrivateKeyFilePath)));
            String certificateContent = new String(Files.readAllBytes(Paths.get(clientCertFilePath)));

            // Convert PEM format to Key and Certificate
            Key privateKey = PrivateKeyConverter.fromPEM(privateKeyContent);
            Certificate[] certChain = CertificateExtractor.fromPEM(certificateContent);

            // 2. Store private key and certificate in the keystore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword.toCharArray());
            keyStore.setKeyEntry("client", privateKey, keystorePassword.toCharArray(), certChain);
            try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
                keyStore.store(fos, keystorePassword.toCharArray());
            }

            // 3. Extract certificate chain and store in the truststore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, truststorePassword.toCharArray());

            // Assuming the first cert is the client's cert and the remaining certs are the chain
            for (int i = 0; i < certChain.length; i++) {
                trustStore.setCertificateEntry("alias" + i, certChain[i]);
            }

            try (FileOutputStream fos = new FileOutputStream(truststorePath)) {
                trustStore.store(fos, truststorePassword.toCharArray());
            }
        }


     catch (Exception e) {
            LOGGER.error("Error during certificate operations.", e);
        }
    }

}

class PrivateKeyConverter {
    public static Key fromPEM(String pemContent) {
        // TODO: Implement conversion logic from PEM string to Key
        return null;
    }
}

class CertificateExtractor {
    public static Certificate[] fromPEM(String pemContent) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certificates = certFactory.generateCertificates(new ByteArrayInputStream(pemContent.getBytes()));
        return certificates.toArray(new Certificate[certificates.size()]);
    }
}

