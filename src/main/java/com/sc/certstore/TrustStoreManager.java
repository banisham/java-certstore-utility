package com.sc.certstore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class TrustStoreManager {
    private static final Logger LOGGER = LoggerFactory.getLogger(TrustStoreManager.class);

    public static void addToTrustStore(String truststorePath, char[] truststorePassword,
                                       String alias, Certificate certificate) {
        try {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, truststorePassword);
            trustStore.setCertificateEntry(alias, certificate);
            try (FileOutputStream fos = new FileOutputStream(truststorePath)) {
                trustStore.store(fos, truststorePassword);
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            LOGGER.error("Failed to add to truststore.", e);
        }
    }
}

