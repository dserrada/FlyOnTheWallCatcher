package org.terra.incognita.fotwc.api;

import com.sun.net.httpserver.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.fail;

public abstract class HTTPSServerBase {

    /**
     * Simple log4j2 logger
     */
    private static final Logger log = LogManager.getLogger(HTTPSServerBase.class);

    /***
     * Start a HTTPS Server for testing
     *
     * @param host                  The hostname/ip where the server will listen for request
     * @param port                  The port where the server will listen for request
     * @param keyStorePath          The path, in classpath, where the keystore used by the server is.
     * @param keyStorePassword      The password for the keystore (null values is the same as no password)
     * @param keyAlias              The alias, in keystore, where the key pair (private and public) of the https server is
     * @param keyPassword           The password of the key pair in keystore (referenced by alias). A null value is the same as no password
     * @return  The started httpsServer
     * @throws IOException  In case of any error in the proccess
     */
    protected HttpsServer startHTTPSServer(String host, int port, String keyStorePath, String keyStorePassword, String keyAlias, String keyPassword) throws IOException {
        log.atTrace().log("on setUp");
        HttpsServer tmpHTTPSServer = null;
        try {
            // Set up the socket address
            InetSocketAddress address = new InetSocketAddress(host, port);

            // Initialise the HTTPS server
            tmpHTTPSServer = HttpsServer.create(address, 0);
            log.atTrace().log("httpsServer created at address {} ", address.toString());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            log.atTrace().log("SSLContext retrieved with protocol {} and class {}", sslContext.getProtocol(), sslContext.getClass().getName());

            // Initialise the keystore
            char[] cKeyPassword = keyPassword == null ? null : keyPassword.toCharArray();
            char[] cKeystorePassword = keyStorePassword == null ? null : keyStorePassword.toCharArray();  // No password
            String caAlias = "goodca";
            String serverCertificateAlias = keyAlias;

            KeyStore ks = KeyStore.getInstance("JKS");
            //FileInputStream fis = new FileInputStream("testing_server_good.keystore");
            InputStream fis = this.getClass().getClassLoader().getResourceAsStream(keyStorePath);
            if (fis != null) {
                log.atTrace().log("Opened input stream size: {}", fis.available());
            } else {
                log.atError().log("Couldn't open keystrore file");
                fail(); // ¿better solution?
            }
            ks.load(fis, cKeystorePassword);
            log.atTrace().log("KeyStore read with aliases: {}", StreamSupport.stream(
                    Spliterators.spliteratorUnknownSize(ks.aliases().asIterator(), Spliterator.ORDERED),
                    false));

            X509Certificate cert = (X509Certificate) ks.getCertificate(serverCertificateAlias);
            log.atTrace().log("Read certificate: {}", cert);

            // Set up the key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, cKeyPassword);

            log.atTrace().log("keyManagerFactory initiated");

            // Set up the trust manager factory
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            log.atTrace().log("turstManagerFactoryInitiated");

            // Set up the HTTPS context and parameters
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            tmpHTTPSServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        log.atDebug().log(params.getProtocols() != null ?
                                Arrays.stream(params.getProtocols()).collect(Collectors.joining(",", "protocols: {", "}"))
                                : "No protocols presents");
                        log.atDebug().log(params.getCipherSuites() != null ?
                                Arrays.stream(params.getCipherSuites()).collect(Collectors.joining(",", "ciphersuites: {", "}"))
                                : "No cipherSuites presents");
                        // Initialise the SSL context
                        SSLContext c = SSLContext.getDefault();
                        SSLEngine engine = c.createSSLEngine();

                        log.atDebug().log(engine.getEnabledProtocols() != null ?
                                Arrays.stream(engine.getEnabledProtocols()).collect(Collectors.joining(",", "protocols: {", "}"))
                                : "Engine has no protocols presents");
                        log.atDebug().log(engine.getEnabledCipherSuites() != null ?
                                Arrays.stream(engine.getEnabledCipherSuites()).collect(Collectors.joining(",", "ciphersuites: {", "}"))
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
            tmpHTTPSServer.createContext("/", new HttpHandler() {
                @Override
                public void handle(HttpExchange httpExchange) throws IOException {
                    String response = "This an automated response: i'm alive and well.... good luck";
                    httpExchange.sendResponseHeaders(200, response.length());
                    OutputStream os = httpExchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            });
            tmpHTTPSServer.start();
            log.atDebug().log("HTTPS Server started at {}:{}", "localhost", 8443);
            try {
                Thread.sleep(3 * 1_000L); // 3s
            } catch (InterruptedException e) {
            }
        } catch (IOException | GeneralSecurityException ioe) {
            log.atError().withThrowable(ioe).log("Failed to create HTTPS server on port " + 8443 + " of localhost");
            throw new IOException(ioe);
        }
        return tmpHTTPSServer;
    }

    /**
     * Stop a HTTPS Server
     *
     * @param server        The server to stop
     * @throws IOException
     */
    void stopHTTPSServer(HttpsServer server) throws IOException {
        if ( server != null ) {
            server.stop(0);
            log.atDebug().log("HTTPS Server stoped");
        }
    }
}
