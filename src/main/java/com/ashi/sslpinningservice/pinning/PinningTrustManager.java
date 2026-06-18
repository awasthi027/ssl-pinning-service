package com.ashi.sslpinningservice.pinning;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * A {@link X509TrustManager} that enforces certificate pinning.
 *
 * <p>This is the heart of client-side SSL pinning. After the normal TLS
 * handshake delivers the server's certificate chain, we compute the pin of
 * the leaf certificate and check it against a set of pins we already trust.
 * If it doesn't match, the connection is aborted.
 *
 * <p>For a learning demo we skip the default CA chain validation (so a
 * self-signed certificate is accepted) and rely purely on the pin. In a real
 * client you would typically run the platform's default validation first and
 * then add this pin check on top.
 */
public class PinningTrustManager implements X509TrustManager {

    private final Set<String> allowedPins;

    public PinningTrustManager(Set<String> allowedPins) {
        if (allowedPins == null || allowedPins.isEmpty()) {
            throw new IllegalArgumentException("At least one pin must be provided");
        }
        this.allowedPins = Set.copyOf(allowedPins);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Server presented an empty certificate chain");
        }

        // The leaf certificate (index 0) is the server's own certificate.
        String presentedPin = CertificatePinUtil.computePin(chain[0]);

        if (!allowedPins.contains(presentedPin)) {
            throw new CertificateException(
                    "Certificate pinning failure. Presented pin " + presentedPin
                            + " does not match any pinned value " + allowedPins);
        }
        // Pin matched -> connection is allowed to proceed.
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // Not used for client-side pinning of a server.
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

