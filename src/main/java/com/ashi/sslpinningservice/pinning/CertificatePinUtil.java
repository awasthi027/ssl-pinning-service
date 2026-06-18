package com.ashi.sslpinningservice.pinning;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Utility for computing a certificate's "pin".
 *
 * <p>The pin is the Base64-encoded SHA-256 hash of the certificate's
 * SubjectPublicKeyInfo (SPKI). This is the same scheme used by the
 * HTTP Public Key Pinning (HPKP) header and by libraries like OkHttp,
 * written as: {@code sha256/<base64>}.
 *
 * <p>Pinning the public key (instead of the whole certificate) means the
 * pin keeps working even when the certificate is renewed, as long as the
 * same key pair is reused.
 */
public final class CertificatePinUtil {

    public static final String PIN_PREFIX = "sha256/";

    private CertificatePinUtil() {
    }

    /** Computes the {@code sha256/<base64>} pin for the given certificate. */
    public static String computePin(X509Certificate certificate) {
        try {
            byte[] spki = certificate.getPublicKey().getEncoded();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(spki);
            return PIN_PREFIX + Base64.getEncoder().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to compute certificate pin", e);
        }
    }
}

