package com.sc.certstore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyStoreManager {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreManager.class);

    public static void addToKeyStore(String keystorePath, char[] keystorePassword,
                                     String alias, Key key, char[] keyPassword,
                                     Certificate[] certificateChain) {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keystorePassword);
            keyStore.setKeyEntry(alias, key, keyPassword, certificateChain);
            try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
                keyStore.store(fos, keystorePassword);
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            LOGGER.error("Failed to add to keystore.", e);
        }
    }
}

