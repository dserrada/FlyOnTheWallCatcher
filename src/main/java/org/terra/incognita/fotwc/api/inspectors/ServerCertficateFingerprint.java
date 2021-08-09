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
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
    public InspectionStatus.StatusCode inspectHTTPSConnection(String hostname, String expectedFingerprint) {
        log.trace("Checking fingerprint of servercertificate to {} expected SHA1" ,hostname, expectedFingerprint);
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null,new TrustManager[] {new MyHostnameVerifier()}, new SecureRandom());

            // See https://www.baeldung.com/java-ssl-handshake-failures
            SocketFactory factory = sc.getSocketFactory();
            try (Socket connection = factory.createSocket(hostname, 443)) {
                SSLSocket sslsocket = (SSLSocket) connection;
                // FIXME: Control ciphers
                sslsocket.setEnabledCipherSuites(new String[] { "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
                // FIXME: Control protocol
                sslsocket.setEnabledProtocols(new String[] { "TLSv1.2"});

                SSLParameters sslParams = new SSLParameters();
                sslParams.setEndpointIdentificationAlgorithm("HTTPS");
                sslsocket.setSSLParameters(sslParams);

                sslsocket.setSoTimeout(5*1000);  // FIXME: Config
                log.trace("Setting sotime");

                log.trace("handksake.protocol: {}",sslsocket.getHandshakeApplicationProtocol());
                SSLSession sslSession = sslsocket.getSession();
                if ( sslSession.getPeerCertificates() != null ) {
                    byte [] data = sslSession.getPeerCertificates()[0].getEncoded();
                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    BigInteger bigInteger = new BigInteger(1, digest.digest(data));
                    String sha1 = bigInteger.toString(16).toUpperCase();
                    log.trace("SHA-1: {} ", sha1);
                    if ( sha1.equalsIgnoreCase(sha1.replace(":","")) ) {
                        log.info("Fingerprint SHA-1 matched...");
                        return InspectionStatus.StatusCode.NO_EAVESDROP_DETECTED;
                    } else {
                        log.error("Fingerprint SHA-1 NOT matched... eavesdrop detected");
                        return InspectionStatus.StatusCode.EAVESDROP_DETECTED;
                    }
                } else {
                    log.error("No peer certificate found...");
                    // FIXME: Throw exception???
                }

                BufferedWriter bos = new BufferedWriter(new OutputStreamWriter(sslsocket.getOutputStream()));
                log.trace("Created writer");
                BufferedReader input = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));
                log.trace("Created reader");

                bos.write("OPTIONS * HTTP/1.1\r\n");
                bos.write(("Host: "+hostname + "\r\n"));
                bos.write("\r\n");
                bos.flush();

                log.trace("Flushed");


                String line = null; // FIXME: Use streams
                while( (line = input.readLine()) != null ) {
                    log.trace(line);
                }

                log.trace("End reading");
            } catch (UnknownHostException e) {
                log.error("UnknownHostException",e);
            } catch (IOException e) {
                log.error("IOException",e);
            }

            log.debug("Secured connection performed successfully");

        } catch (NoSuchAlgorithmException | KeyManagementException | CertificateEncodingException e) {
            log.error("NoSuchAlgorithmException error",e);
        }
        return null;
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
