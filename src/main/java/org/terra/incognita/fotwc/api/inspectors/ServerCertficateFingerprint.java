// Copyright 2021 - David Pérez Serrada
package org.terra.incognita.fotwc.api.inspectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.terra.incognita.fotwc.api.EavesdropInspector;
import org.terra.incognita.fotwc.api.InspectionStatus;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Check for eavesdrop by checking the fingerprint of the server certificate
 */
public class ServerCertficateFingerprint implements EavesdropInspector {

    /**
     * Simple log4j2 logger
     */
    private static final Logger log = LogManager.getLogger(ServerCertficateFingerprint.class);

    @Override
    public InspectionStatus.StatusCode inspectHTTPSConnection(String hostname, int port, String expectedFingerprint) {
        log.atTrace().log("Checking fingerprint of servercertificate to {} expected SHA1" ,hostname, expectedFingerprint);
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null,new TrustManager[] {new MyHostnameVerifier()}, new SecureRandom());

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(getClass().getResourceAsStream("testng_client.keystore"), new char [] {});

            // See https://www.baeldung.com/java-ssl-handshake-failures
            SocketFactory factory = sc.getSocketFactory();
            try (Socket connection = factory.createSocket(hostname, port)) {
                SSLSocket sslsocket = (SSLSocket) connection;
                // FIXME: Control ciphers
                sslsocket.setEnabledCipherSuites(new String[] { "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
                // FIXME: Control protocol
                sslsocket.setEnabledProtocols(new String[] { "TLSv1.2"});

                SSLParameters sslParams = new SSLParameters();
                sslParams.setEndpointIdentificationAlgorithm("HTTPS");
                sslsocket.setSSLParameters(sslParams);

                sslsocket.setSoTimeout(5*1000);  // FIXME: Config
                log.atTrace().log("Setting sotime");

                log.atTrace().log("handksake.protocol: {}",sslsocket.getHandshakeApplicationProtocol());
                SSLSession sslSession = sslsocket.getSession();
                if ( sslSession.getPeerCertificates() != null ) {
                    byte [] data = sslSession.getPeerCertificates()[0].getEncoded();
                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    BigInteger bigInteger = new BigInteger(1, digest.digest(data));
                    String sha1 = bigInteger.toString(16).toUpperCase();
                    log.atTrace().log("SHA-1: {} ", sha1);
                    if ( sha1.equalsIgnoreCase(sha1.replace(":","")) ) {
                        log.info("Fingerprint SHA-1 matched...");
                        return InspectionStatus.StatusCode.NO_EAVESDROP_DETECTED;
                    } else {
                        log.error("Fingerprint SHA-1 NOT matched... eavesdrop detected");
                        return InspectionStatus.StatusCode.EAVESDROP_DETECTED;
                    }
                } else {
                    log.atError().log("No peer certificate found...");
                    // FIXME: Throw exception???
                }

                sendSomeData(hostname, sslsocket);
            } catch (IOException e) {
                log.atError().withThrowable(e).log("UnknownHostException");
            }

            log.atDebug().log("Secured connection performed successfully");

        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException | CertificateException | IOException e) {
            log.error("NoSuchAlgorithmException error",e);
        }
        return null;
    }

    /**
     * Send some data through sockets.
     *
     * @param hostname      The hostname
     * @param sslsocket
     * @throws IOException
     */
    private void sendSomeData(String hostname, SSLSocket sslsocket) throws IOException {
        BufferedWriter bos = new BufferedWriter(new OutputStreamWriter(sslsocket.getOutputStream()));
        log.atTrace().log("Created writer");
        BufferedReader input = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));
        log.atTrace().log("Created reader");

        bos.write("""
        OPTIONS * HTTP/1.1
        Host: %s 
        """.formatted(hostname));
        bos.flush();

        log.atTrace().log("Waiting for remote response");
        log.atTrace().log("---------------------------");
        input.lines().forEach( l -> log.atTrace().log(l));
        log.atTrace().log("---------------------------");
    }

    private static class MyHostnameVerifier extends X509ExtendedTrustManager {

        /**
         * Simple log4j2 logger
         */
        private static final Logger log = LogManager.getLogger(MyHostnameVerifier.class);

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
            log.trace("checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) - No checking client's certificate");

        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
            log.trace("checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket)");
            if ( x509Certificates != null ) {
                log.debug("checkServerTrusted - firstCertificate: serialNumber: {} ",x509Certificates[0].getSerialNumber().toString(16).toLowerCase());
            } else {
                log.error("checkServerTrusted - Couldn't get certificate");
            }
            // THIS IS THE METHOD TO IMPLEMENT
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
            log.trace("heckClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) - No checking client's certificate");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
            log.trace("checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine)");
        }


        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            log.trace("checkClientTrusted(X509Certificate[] x509Certificates, String s) - No checking client's certificate");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            log.trace("checkServerTrusted - s: {}",s);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            log.debug("getAcceptedIssuers ");
            return new X509Certificate[0];
        }
    }


}
