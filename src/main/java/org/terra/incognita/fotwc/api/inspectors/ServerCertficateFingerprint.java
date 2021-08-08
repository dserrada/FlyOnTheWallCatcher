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
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
    public InspectionStatus inspectHTTPSConnection(String hostname) {
        log.trace("Checking fingerprint of servercertificate to {}",hostname);
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null,new TrustManager[] {new HostnameVerifier()}, new SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            /*
            HttpsURLConnection.setDefaultHostnameVerifier((s,session) -> {
                log.trace("setDefaultHostnameVerifier - s {}",s);
                return true;
            });
             */

            // See https://www.baeldung.com/java-ssl-handshake-failures
            SocketFactory factory = SSLSocketFactory.getDefault();
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
                    byte [] data = sslSession.getPeerCertificates()[0].getPublicKey().getEncoded();
                    BigInteger bigIntegerData = new BigInteger(1, data);
                    log.trace("Bytes: " + bigIntegerData.toString(16).toLowerCase());
                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    BigInteger bigInteger = new BigInteger(1, digest.digest(data));
                    log.trace("Bytes: " + bigInteger.toString(16).toLowerCase());
                }

                BufferedWriter bos = new BufferedWriter(new OutputStreamWriter(sslsocket.getOutputStream()));
                log.trace("Created writer");
                BufferedReader input = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));
                log.trace("Created reader");

                bos.write("GET / HTTP/1.1\r\n");
                bos.write(("Host: "+hostname + "\r\n"));
                bos.write("\r\n");
                bos.flush();

                log.trace("Flushed");


                String line = null; // FIXME: Use streams
                while( (line = input.readLine()) != null ) {
                    // log.trace(line);
                }

                log.trace("End reading");
            } catch (UnknownHostException e) {
                log.error("UnknownHostException",e);
            } catch (IOException e) {
                log.error("IOException",e);
            }

            log.debug("Secured connection performed successfully");

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            log.error("NoSuchAlgorithmException error",e);
        }
        return null;
    }

    private static class HostnameVerifier implements X509TrustManager {

        /**
         * Simple log4j2 logger
         */
        private static final Logger log = LogManager.getLogger(HostnameVerifier.class);

        public HostnameVerifier() {
            log.debug("HostnameVerifier - Constructor");
        }


        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            log.trace("checkClientTrusted - s: {}",s);
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
