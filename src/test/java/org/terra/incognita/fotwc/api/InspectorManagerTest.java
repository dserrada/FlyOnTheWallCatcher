package org.terra.incognita.fotwc.api;

import com.sun.net.httpserver.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.terra.incognita.fotwc.cli.Main;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.*;

class InspectorManagerTest {

    /**
     * Simple log4j2 logger
     */
    private static final Logger log = LogManager.getLogger(InspectorManagerTest.class);

    /**
     * The server against
     */
    private HttpsServer httpsServer;

    @BeforeEach
    void setUp() throws IOException {
        log.atTrace().log("on setUp");
        try {
            // Set up the socket address
            InetSocketAddress address = new InetSocketAddress( "localhost",8443);

            // Initialise the HTTPS server
            httpsServer = HttpsServer.create(address, 0);
            log.atTrace().log("httpsServer created at address {} ", address.toString());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            log.atTrace().log("SSLContext retrieved with protocol {} and class {}", sslContext.getProtocol(),sslContext.getClass().getName());

            // Initialise the keystore
            char [] keyPassword = "password".toCharArray(); // FIXME: fixed???
            char [] keystorePassword = null;  // No password
            String caAlias = "goodca";
            String serverCertificateAlias = "localhost:8443 (goodca)";

            KeyStore ks = KeyStore.getInstance("JKS");
            //FileInputStream fis = new FileInputStream("testing_server_good.keystore");
            InputStream fis = this.getClass().getClassLoader().getResourceAsStream("testing_server_good.keystore");
            if ( fis != null ) {
                log.atTrace().log("Opened input stream size: {}", fis.available());
            } else {
                log.atError().log("Couldn't open keystrore file");
                fail(); // ¿better solution?
            }
            ks.load(fis, keystorePassword);
            log.atTrace().log("KeyStore read with aliases: {}", StreamSupport.stream(
                    Spliterators.spliteratorUnknownSize(ks.aliases().asIterator(), Spliterator.ORDERED),
                    false));

            X509Certificate cert = (X509Certificate) ks.getCertificate(serverCertificateAlias);
            log.atTrace().log("Read certificate: {}",cert);

            // Set up the key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keyPassword);

            log.atTrace().log("keyManagerFactory initiated");

            // Set up the trust manager factory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            log.atTrace().log("turstManagerFactoryInitiated");

            // Set up the HTTPS context and parameters
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        log.atDebug().log(params.getProtocols() != null ?
                                Arrays.stream(params.getProtocols()).collect(Collectors.joining(",","protocols: {","}"))
                                : "No protocols presents");
                        log.atDebug().log(params.getCipherSuites() != null ?
                                Arrays.stream(params.getCipherSuites()).collect(Collectors.joining(",","ciphersuites: {","}"))
                                : "No cipherSuites presents");
                        // Initialise the SSL context
                        SSLContext c = SSLContext.getDefault();
                        SSLEngine engine = c.createSSLEngine();

                        log.atDebug().log(engine.getEnabledProtocols() != null ?
                                Arrays.stream(engine.getEnabledProtocols()).collect(Collectors.joining(",","protocols: {","}"))
                                : "Engine has no protocols presents");
                        log.atDebug().log(engine.getEnabledCipherSuites() != null ?
                                Arrays.stream(engine.getEnabledCipherSuites()).collect(Collectors.joining(",","ciphersuites: {","}"))
                                : "Engine has no cipherSuites presents");
                        params.setNeedClientAuth(false);
                        params.setWantClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());


                        // Get the default parameters
                        SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                        params.setSSLParameters(defaultSSLParameters);
                    } catch (Exception ex) {
                        log.atError().withThrowable(ex).log("Failed to create HTTPS server");
                    }
                }
            });
            httpsServer.createContext("/", new HttpHandler() {
                @Override
                public void handle(HttpExchange httpExchange) throws IOException {
                    String response = "This an automated response: i'm alive and well.... good luck";
                    httpExchange.sendResponseHeaders(200, response.length());
                    OutputStream os = httpExchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            });
            httpsServer.start();
            log.atDebug().log("HTTPS Server started at {}:{}","localhost", 8443);
            try {
                Thread.sleep(3*1_000L); // 3s
            } catch (InterruptedException e) {}
        } catch (IOException | GeneralSecurityException ioe) {
            log.atError().withThrowable(ioe).log("Failed to create HTTPS server on port " + 8443 + " of localhost");
            throw new IOException(ioe);
        }
    }

    @AfterEach
    void tearDown() throws IOException {
        httpsServer.stop(0);
        log.atDebug().log("HTTPS Server stop");
    }

    @Test
    void inspectConnection() {
        log.atDebug().log("Starting test");
        Main config = new Main();
        InspectorManager im = new InspectorManager(config);
        InspectionStatus.StatusCode statusCode = im.inspectConnection("localhost",8443,"1F4FCC87A3866565C83FC1A90A1E194521E51B50");
        log.atDebug().log("Ending test");
    }
}