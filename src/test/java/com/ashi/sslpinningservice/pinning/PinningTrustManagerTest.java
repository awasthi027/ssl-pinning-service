package com.ashi.sslpinningservice.pinning;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for client-side pinning validation, i.e. the decision the client
 * makes about whether to trust the server's certificate during the TLS
 * handshake.
 */
class PinningTrustManagerTest {

    @Test
    void acceptsServerWhosePinIsAllowed() throws Exception {
        X509Certificate serverCert = CertificateTestSupport.randomCertificate();
        String goodPin = CertificatePinUtil.computePin(serverCert);
        PinningTrustManager trustManager = new PinningTrustManager(Set.of(goodPin));

        assertThatCode(() -> trustManager.checkServerTrusted(
                new X509Certificate[]{serverCert}, "RSA"))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsServerWhosePinIsNotAllowed() throws Exception {
        // The pin we trust belongs to a different certificate/key.
        X509Certificate trustedCert = CertificateTestSupport.randomCertificate();
        String trustedPin = CertificatePinUtil.computePin(trustedCert);
        PinningTrustManager trustManager = new PinningTrustManager(Set.of(trustedPin));

        X509Certificate attackerCert = CertificateTestSupport.randomCertificate();

        assertThatThrownBy(() -> trustManager.checkServerTrusted(
                new X509Certificate[]{attackerCert}, "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("Certificate pinning failure");
    }

    @Test
    void acceptsWhenLeafMatchesOneOfMultiplePins() throws Exception {
        // Real clients ship a backup pin; any one match should pass.
        X509Certificate serverCert = CertificateTestSupport.randomCertificate();
        String currentPin = CertificatePinUtil.computePin(serverCert);
        String backupPin = CertificatePinUtil.computePin(
                CertificateTestSupport.randomCertificate());
        PinningTrustManager trustManager =
                new PinningTrustManager(Set.of(backupPin, currentPin));

        assertThatCode(() -> trustManager.checkServerTrusted(
                new X509Certificate[]{serverCert}, "RSA"))
                .doesNotThrowAnyException();
    }

    @Test
    void validatesOnlyTheLeafCertificate() throws Exception {
        // The leaf (index 0) is pinned; the rest of the chain is irrelevant.
        X509Certificate leaf = CertificateTestSupport.randomCertificate();
        X509Certificate intermediate = CertificateTestSupport.randomCertificate();
        String leafPin = CertificatePinUtil.computePin(leaf);
        PinningTrustManager trustManager = new PinningTrustManager(Set.of(leafPin));

        assertThatCode(() -> trustManager.checkServerTrusted(
                new X509Certificate[]{leaf, intermediate}, "RSA"))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsEmptyCertificateChain() {
        PinningTrustManager trustManager =
                new PinningTrustManager(Set.of("sha256/whatever"));

        assertThatThrownBy(() -> trustManager.checkServerTrusted(
                new X509Certificate[0], "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("empty certificate chain");
    }

    @Test
    void rejectsNullCertificateChain() {
        PinningTrustManager trustManager =
                new PinningTrustManager(Set.of("sha256/whatever"));

        assertThatThrownBy(() -> trustManager.checkServerTrusted(null, "RSA"))
                .isInstanceOf(CertificateException.class);
    }

    @Test
    void constructorRejectsEmptyPinSet() {
        assertThatThrownBy(() -> new PinningTrustManager(Set.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("At least one pin");
    }

    @Test
    void constructorRejectsNullPinSet() {
        assertThatThrownBy(() -> new PinningTrustManager(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void exposesNoAcceptedIssuers() {
        PinningTrustManager trustManager =
                new PinningTrustManager(Set.of("sha256/whatever"));

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
    }

    @Test
    void usesPublicKeyPinSoRenewedCertWithSameKeyStillTrusted() throws Exception {
        // Public-key (SPKI) pinning: a renewed cert that reuses the key still matches.
        KeyPair sharedKey = CertificateTestSupport.newKeyPair();
        X509Certificate oldCert = CertificateTestSupport.selfSigned(sharedKey);
        X509Certificate renewedCert = CertificateTestSupport.selfSigned(sharedKey);

        String pin = CertificatePinUtil.computePin(oldCert);
        PinningTrustManager trustManager = new PinningTrustManager(Set.of(pin));

        assertThatCode(() -> trustManager.checkServerTrusted(
                new X509Certificate[]{renewedCert}, "RSA"))
                .doesNotThrowAnyException();
    }
}

