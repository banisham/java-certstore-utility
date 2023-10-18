package com.sc.certstore.util;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

public class CertificateExtractor {

    public static Certificate[] extractCertificateChain(String pem) throws Exception {
        String[] pemCerts = pem.split("-----END CERTIFICATE-----");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<Certificate> certList = new ArrayList<>();

        for (String cert : pemCerts) {
            if (cert != null && !cert.trim().isEmpty()) {
                cert = cert + "-----END CERTIFICATE-----";
                ByteArrayInputStream bais = new ByteArrayInputStream(cert.getBytes());
                certList.add(factory.generateCertificate(bais));
            }
        }

        return certList.toArray(new Certificate[0]);
    }
}


