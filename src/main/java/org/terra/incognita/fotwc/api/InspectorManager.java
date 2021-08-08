// Copyright 2021 - David Pérez Serrada
package org.terra.incognita.fotwc.api;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.terra.incognita.fotwc.api.inspectors.ServerCertficateFingerprint;
import org.terra.incognita.fotwc.cli.Main;

/**
 * Manage the various inspectors that try to catch a MitM
 *
 * @author David Pérez Serrada
 */
public class InspectorManager {

    /**
     * Simple log4j2 logger
     */
    private static final Logger log = LogManager.getLogger(InspectorManager.class);

    /**
     * Configuration to use in the inspections
     */
    private Main config;


    /**
     * Initialize the inspectors
     */
    public InspectorManager(Main config) {
        log.trace("Initializing Inspector manager");
        this.config = config;
    }


    public void inspectConnection(String hostname) {
        log.debug("Testing connection to host {}",hostname);
        // FIXME: Customize to support various inspectors
        ServerCertficateFingerprint fingerprint = new ServerCertficateFingerprint();
        fingerprint.inspectHTTPSConnection(hostname);
    }

}
