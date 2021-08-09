// Copyright 2021 - David Pérez Serrada
package org.terra.incognita.fotwc.api;

/**
 * Eavesdrop detector
 */
public interface EavesdropInspector {

    /**
     * Look for an eavesdrop in a https connection to a hostname
     *
     * @param hostname  The hostname where a https connection is made.
     * @return The status of the detection process.
     */
    public InspectionStatus.StatusCode inspectHTTPSConnection(String hostname, String expectedFingerprint);
}
