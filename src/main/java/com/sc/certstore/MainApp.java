package com.sc.certstore;

import com.sc.certstore.util.CertificateExtractor;
import com.sc.certstore.util.PrivateKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import javax.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

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
            String clientPem = new String(Files.readAllBytes(Paths.get(clientCertFilePath)));
            String clientPrivateKeyPem = new String(Files.readAllBytes(Paths.get(clientPrivateKeyFilePath)));

            Certificate clientCert = CertificateConverter.convertPEMToCertificate(clientPem);
            PrivateKey clientPrivateKey = PrivateKeyConverter.convertPEMToPrivateKey(clientPrivateKeyPem);

            if (clientCert != null && clientPrivateKey != null) {
                Certificate[] chain = {clientCert};

                // Add your own certificate and private key to keystore
                KeyStoreManager.addToKeyStore(keystorePath, keystorePassword.toCharArray(), "clientAlias", clientPrivateKey, keyPassword.toCharArray(), chain);

                // Extract the chain from the client certificate and add to the truststore
                Certificate[] extractedChain = CertificateExtractor.extractCertificateChain(clientPem);
                for (Certificate cert : extractedChain) {
                    if (cert != null) {
                        TrustStoreManager.addToTrustStore(truststorePath, truststorePassword.toCharArray(), "alias" + ((X509Certificate) cert).getSerialNumber(), cert);
                    } else {
                        LOGGER.error("Certificate retuned from the CA chain is null");
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error during certificate operations.", e);
        }
    }
}

