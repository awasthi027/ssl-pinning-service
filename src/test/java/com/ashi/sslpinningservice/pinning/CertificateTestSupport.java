package com.ashi.sslpinningservice.pinning;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Test helpers that build genuine self-signed {@link X509Certificate}s so the
 * pinning logic can be exercised against real certificates (no mocking of JDK
 * security classes, which newer JDKs forbid).
 */
final class CertificateTestSupport {

    private CertificateTestSupport() {
    }

    /** Generates a fresh 2048-bit RSA key pair. */
    static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /** Builds a self-signed certificate for a brand new key pair. */
    static X509Certificate randomCertificate() throws Exception {
        return selfSigned(newKeyPair());
    }

    /**
     * Builds a self-signed certificate around the given key pair. Reusing the
     * same key pair across calls produces certificates that share the same
     * public key (and therefore the same SPKI pin).
     */
    static X509Certificate selfSigned(KeyPair keyPair) throws Exception {
        X500Principal subject = new X500Principal("CN=test");
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 1000L);
        Date notAfter = new Date(now + 365L * 24 * 60 * 60 * 1000);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now),
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
    }
}

