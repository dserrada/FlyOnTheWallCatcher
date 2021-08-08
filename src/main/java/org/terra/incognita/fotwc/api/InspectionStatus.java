// Copyright 2021 - David Pérez Serrada
package org.terra.incognita.fotwc.api;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Status of a MitM detection
 */
public class InspectionStatus {
    /**
     * Simple log4j2 logger
     */
    private static final Logger log = LogManager.getLogger(InspectionStatus.class);

    /**
     * Type of result in the detection process
     */
    public enum StatusCode {
        /**
         * No eavesdrop detected.
         *
         * Of course, this not means that there was no eavesdrop
         */
        NO_EAVESDROP_DETECTED,
        /**
         * No eavesdrop detected, but some suspicious pattern was found
         */
        EAVESDROP_WARNING,

        /**
         * An eavesdrop was detected.
         */
        EAVESDROP_DETECTED,
    }
}
