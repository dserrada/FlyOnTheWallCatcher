package org.terra.incognita.fotwc.cli;


import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;


/**
 * Command line launcher
 *
 * @author dserrada@gmail.com
 */
public class Main {

    /**
     * Simple log4j2 logger
     */
    private static final Logger log = LogManager.getLogger(Main.class);

    public static void main(final String... args) {
        log.debug("Init logging system");
        // Only a little test with log4j2 and lambda expression
        log.trace("Running program in directory {} ", () ->  new File("").getAbsolutePath());
        log.debug("Shutting down");
    }



}
