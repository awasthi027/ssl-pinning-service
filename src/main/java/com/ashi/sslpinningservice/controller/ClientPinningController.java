package com.ashi.sslpinningservice.controller;

import com.ashi.sslpinningservice.service.PinningService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Endpoints for the client-pinning learning demo.
 *
 * <p>The app serves plain HTTP on {@code ${PORT}} (what a PaaS edge proxy talks
 * to) and a separate internal HTTPS connector with the self-signed certificate.
 * {@code /api/secure/ping} is the resource we pin against, and the single
 * {@code /api/client/verify} endpoint drives a pinned HTTPS call to the internal
 * HTTPS connector so you can watch pinning succeed and fail with one API.
 */
@RestController
public class ClientPinningController {

    private final PinningService pinningService;
    private final String secureUrl;

    public ClientPinningController(PinningService pinningService,
                                   @Value("${demo.secure-url}") String secureUrl) {
        this.pinningService = pinningService;
        this.secureUrl = secureUrl;
    }

    /** The protected resource that the pinned client connects to. */
    @GetMapping("/api/secure/ping")
    public Map<String, Object> ping() {
        return Map.of(
                "message", "pong over a pinned TLS connection",
                "secure", true);
    }

    /**
     * Single endpoint that performs a pinned HTTPS call to the secure resource.
     *
     * <p>Behaviour is driven entirely by the optional {@code pin} parameter:
     * <ul>
     *   <li>omit it &rarr; the server's real (correct) pin is used &rarr; the
     *       call <b>succeeds</b> (200 with the real body);</li>
     *   <li>pass {@code ?pin=sha256/...} with a wrong value &rarr; pinning
     *       <b>rejects</b> the connection with a {@code CertificateException}.</li>
     * </ul>
     *
     * <p>The response always echoes {@code expectedPin} so you can see the
     * known-good value next to the one that was actually used.
     */
    @PostMapping("/api/client/verify")
    public Map<String, Object> verify(@RequestParam(required = false) String pin) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            String expectedPin = pinningService.expectedServerPin();
            String pinToUse = (pin == null || pin.isBlank()) ? expectedPin : pin;
            result.put("expectedPin", expectedPin);
            result.put("pinUsed", pinToUse);

            PinningService.PinnedCallResult call =
                    pinningService.get(secureUrl, Set.of(pinToUse));
            result.put("pinningPassed", true);
            result.put("statusCode", call.statusCode());
            result.put("responseBody", call.body());
        } catch (Exception e) {
            result.put("pinningPassed", false);
            result.put("error", rootCause(e));
        }
        return result;
    }

    private static String rootCause(Throwable t) {
        Throwable cur = t;
        while (cur.getCause() != null && cur.getCause() != cur) {
            cur = cur.getCause();
        }
        return cur.getClass().getSimpleName() + ": " + cur.getMessage();
    }
}

