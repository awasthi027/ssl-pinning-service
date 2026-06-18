package com.ashi.sslpinningservice.service;

import com.ashi.sslpinningservice.pinning.CertificatePinUtil;
import com.ashi.sslpinningservice.pinning.PinningTrustManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Enumeration;
import java.util.Set;

/**
 * Demonstrates client-side SSL pinning using the JDK's {@link HttpClient}.
 *
 * <p>It builds an {@link SSLContext} backed by a {@link PinningTrustManager}
 * so that an HTTPS call only succeeds when the server presents a certificate
 * whose public-key pin is in our allow-list.
 */
@Service
public class PinningService {

    private final Resource keyStore;
    private final char[] keyStorePassword;

    public PinningService(
            @Value("${demo.ssl.key-store}") Resource keyStore,
            @Value("${demo.ssl.key-store-password}") String keyStorePassword) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword.toCharArray();
    }

    /**
     * Reads the self-signed server certificate from the keystore and returns
     * its expected pin. Handy for the demo so the client knows the "good" pin.
     */
    public String expectedServerPin() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = keyStore.getInputStream()) {
            ks.load(in, keyStorePassword);
        }
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.getCertificate(alias) instanceof X509Certificate cert) {
                return CertificatePinUtil.computePin(cert);
            }
        }
        throw new IllegalStateException("No X.509 certificate found in keystore");
    }

    /**
     * Makes a pinned HTTPS GET request to {@code url}, trusting only servers
     * whose leaf certificate pin is contained in {@code allowedPins}.
     */
    public PinnedCallResult get(String url, Set<String> allowedPins) throws Exception {
        TrustManager[] trustManagers = {new PinningTrustManager(allowedPins)};
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers, new SecureRandom());

        HttpClient client = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());
        return new PinnedCallResult(response.statusCode(), response.body());
    }

    /** Simple immutable holder for a pinned call's outcome. */
    public record PinnedCallResult(int statusCode, String body) {
    }
}

