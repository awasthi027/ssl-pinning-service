# ssl-pinning-service

A small, self-contained Spring Boot project to **learn how client-side SSL
pinning works**, using a **self-signed certificate**.

The app plays both roles in one process:

- It **serves HTTPS** on `:8443` using a self-signed certificate (the server
  being pinned).
- It acts as a **pinned client** that calls back into that HTTPS endpoint and
  only trusts the server if the certificate's public-key pin matches.

## What "client pinning" means here

In normal HTTPS the client trusts any server whose certificate is signed by a
trusted CA. With **pinning**, the client additionally requires the server's
certificate to match a known **pin** — the Base64 SHA-256 hash of the
certificate's public key (SPKI), written as `sha256/<base64>`.

The check lives in a custom `X509TrustManager`
([`PinningTrustManager`](src/main/java/com/ashi/sslpinningservice/pinning/PinningTrustManager.java)):
after the TLS handshake hands over the server's certificate chain, we compute
the leaf certificate's pin and reject the connection if it isn't in our
allow-list.

## Project layout

| File | Role |
|------|------|
| `pinning/CertificatePinUtil.java` | Computes the `sha256/...` pin from a certificate |
| `pinning/PinningTrustManager.java` | Custom trust manager that enforces the pin |
| `service/PinningService.java` | Builds a pinned `HttpClient` and makes the call |
| `controller/ClientPinningController.java` | Demo REST endpoints |
| `resources/application.properties` | Enables HTTPS with the self-signed keystore |

## Prerequisites

- JDK 21+
- Maven 3.9+

## Generate the self-signed certificate

A keystore is generated with a known password (`changeit`) and `localhost` SAN:

```bash
keytool -genkeypair \
  -alias ssl-pinning-demo \
  -keyalg RSA -keysize 2048 -validity 3650 \
  -storetype PKCS12 -keystore certs/server.p12 -storepass changeit \
  -dname "CN=localhost, OU=Learning, O=Ashi, L=NA, ST=NA, C=NA" \
  -ext "SAN=dns:localhost,ip:127.0.0.1"
```

## Build & run

```bash
mvn -DskipTests clean package
java -jar target/ssl-pinning-service-1.0.0.jar
```

The service starts on `https://localhost:8443` (self-signed, so use `curl -k`).

## Try it

```bash
# Pinned call with the CORRECT pin (no param) -> succeeds (200, real body)
curl -sk -X POST https://localhost:8443/api/client/verify

# Pinned call with a WRONG pin -> rejected with a CertificateException
curl -sk -X POST "https://localhost:8443/api/client/verify?pin=sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

Example outputs:

```jsonc
// correct pin (no ?pin)
{ "expectedPin":"sha256/vCOI...7J8=", "pinUsed":"sha256/vCOI...7J8=",
  "pinningPassed":true, "statusCode":200,
  "responseBody":"{\"secure\":true,\"message\":\"pong over a pinned TLS connection\"}" }

// wrong pin
{ "expectedPin":"sha256/vCOI...7J8=", "pinUsed":"sha256/AAAA...AAA=",
  "pinningPassed":false, "error":"CertificateException: Certificate pinning failure..." }
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/secure/ping` | The protected resource the client pins against (the target server) |
| `POST` | `/api/client/verify` | The **single** pinning demo endpoint. Omit `pin` for the correct value (succeeds); pass `?pin=sha256/...` with a wrong value (rejected). |

## Notes for real-world use

- Prefer **public-key (SPKI) pinning** over whole-certificate pinning so the pin
  survives certificate renewal when the key is reused.
- Always ship **at least one backup pin** so a key rotation can't permanently
  lock out clients.
- This demo trusts purely on the pin (so a self-signed cert is accepted). In
  production, run the platform's normal CA/hostname validation **first**, then
  add the pin check on top.

## Implemented three API 
1. make to request to server "api/secure/ping" and server send response back to client, client read ssl certificate from challenge and verify we can trust the server 
2. We just make a call to server and server added server pins in SSL context and make http request as pretent as client call first api "api/secure/ping" to validate. We can trust to server as client or not.
3. This API as wrong pin.


