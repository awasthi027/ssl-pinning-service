package com.ashi.sslpinningservice.pinning;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class CertificatePinUtilTest {

    @Test
    void pinUsesSha256PrefixAndValidBase64() throws Exception {
        X509Certificate cert = CertificateTestSupport.randomCertificate();

        String pin = CertificatePinUtil.computePin(cert);

        assertThat(pin).startsWith("sha256/");
        String base64 = pin.substring("sha256/".length());
        // A SHA-256 digest is 32 bytes -> decodes cleanly.
        assertThat(Base64.getDecoder().decode(base64)).hasSize(32);
    }

    @Test
    void pinIsDeterministicForSameKey() throws Exception {
        KeyPair keyPair = CertificateTestSupport.newKeyPair();
        X509Certificate certA = CertificateTestSupport.selfSigned(keyPair);
        X509Certificate certB = CertificateTestSupport.selfSigned(keyPair);

        assertThat(CertificatePinUtil.computePin(certA))
                .isEqualTo(CertificatePinUtil.computePin(certB));
    }

    @Test
    void pinDiffersForDifferentKeys() throws Exception {
        X509Certificate cert1 = CertificateTestSupport.randomCertificate();
        X509Certificate cert2 = CertificateTestSupport.randomCertificate();

        assertThat(CertificatePinUtil.computePin(cert1))
                .isNotEqualTo(CertificatePinUtil.computePin(cert2));
    }
}

