package com.sc.certstore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class CertificateConverter {
    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateConverter.class);

    public static Certificate convertPEMToCertificate(String pem) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return factory.generateCertificate(new ByteArrayInputStream(pem.getBytes()));
        } catch (CertificateException e) {
            LOGGER.error("Failed to convert PEM to certificate.", e);
            return null;
        }
    }
}

