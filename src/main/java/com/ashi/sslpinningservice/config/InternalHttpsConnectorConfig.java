package com.ashi.sslpinningservice.config;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Adds a SECOND, internal HTTPS connector alongside the main plain-HTTP
 * connector.
 *
 * <p>On platforms like Railway the public connector must speak plain HTTP
 * (the platform terminates public TLS at its edge), so the main app listens on
 * {@code ${PORT}} over HTTP. This extra connector serves the self-signed
 * certificate over HTTPS on {@code demo.https.port} purely so the client-side
 * SSL pinning demo has a real TLS endpoint to connect to internally.
 */
@Configuration
public class InternalHttpsConnectorConfig {

    @Value("${demo.https.port:8443}")
    private int httpsPort;

    @Value("${demo.ssl.key-store}")
    private String keyStore;

    @Value("${demo.ssl.key-store-password}")
    private String keyStorePassword;

    @Value("${demo.ssl.key-alias}")
    private String keyAlias;

    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        factory.addAdditionalTomcatConnectors(httpsConnector());
        return factory;
    }

    private Connector httpsConnector() {
        Connector connector = new Connector(Http11NioProtocol.class.getName());
        connector.setScheme("https");
        connector.setSecure(true);
        connector.setPort(httpsPort);

        Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
        protocol.setSSLEnabled(true);

        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(sslHostConfig, Type.UNDEFINED);
        certificate.setCertificateKeystoreFile(resolveKeystorePath());
        certificate.setCertificateKeystorePassword(keyStorePassword);
        certificate.setCertificateKeyAlias(keyAlias);
        certificate.setCertificateKeystoreType("PKCS12");
        sslHostConfig.addCertificate(certificate);
        connector.addSslHostConfig(sslHostConfig);

        return connector;
    }

    /**
     * Copies the keystore (which may live inside the JAR on the classpath) to a
     * temp file, because Tomcat's connector needs a real filesystem path.
     */
    private String resolveKeystorePath() {
        try (InputStream in = new DefaultResourceLoader().getResource(keyStore).getInputStream()) {
            Path temp = Files.createTempFile("ssl-pinning-keystore", ".p12");
            temp.toFile().deleteOnExit();
            Files.copy(in, temp, StandardCopyOption.REPLACE_EXISTING);
            return temp.toAbsolutePath().toString();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load keystore: " + keyStore, e);
        }
    }
}

