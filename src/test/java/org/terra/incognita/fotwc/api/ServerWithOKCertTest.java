package org.terra.incognita.fotwc.api;

import com.sun.net.httpserver.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.terra.incognita.fotwc.cli.Main;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ServerWithOKCertTest extends HTTPSServerBase {

    /**
     * Simple log4j2 logger
     */
    private static final Logger log = LogManager.getLogger(ServerWithOKCertTest.class);

    /**
     * The server against
     */
    private HttpsServer httpsServer;

    @BeforeEach
    void setUp() throws IOException {
        httpsServer = startHTTPSServer("localhost",8443,"testing_server_good.keystore",null, "localhost:8443 (goodca)","password");
    }

    @AfterEach
    void tearDown() throws IOException {
        stopHTTPSServer(httpsServer);
    }

    @Test
    void inspectConnection() {
        log.atDebug().log("Starting test");
        Main config = new Main();
        InspectorManager im = new InspectorManager(config);
        InspectionStatus.StatusCode statusCode = im.inspectConnection("localhost",8443,
                "1F4FCC87A3866565C83FC1A90A1E194521E51B50");
        assertEquals(statusCode,InspectionStatus.StatusCode.NO_EAVESDROP_DETECTED);
        log.atDebug().log("Ending test");
    }
}