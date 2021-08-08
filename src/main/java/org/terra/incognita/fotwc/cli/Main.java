// Copyright 2021 - David Pérez Serrada
package org.terra.incognita.fotwc.cli;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.terra.incognita.fotwc.api.InspectorManager;
import picocli.CommandLine;

import java.io.File;


/**
 * Command line launcher
 *
 * @author dserrada@gmail.com
 */
@CommandLine.Command(name = "fotwc",
        mixinStandardHelpOptions = true, version = "0.1",
        description = "A Man In The Middle detector")
public class Main {

    /**
     * Simple log4j2 logger
     */
    private static final Logger log = LogManager.getLogger(Main.class);

    /**
     * Set log level (true -> trace, false -> error)
     */
    @CommandLine.Option(names = {"-v", "--verbose"}, description = "Set log level to debug")
    private boolean verbose = false;

    public static void main(final String... args) {
        log.debug("Init logging system");
        // Read the command line options
        Main config = CommandLine.populateCommand(new Main(), args);

        log.debug("Command options, verbose: {}",config.verbose);

        if (config.verbose) {
            Configurator.setRootLevel(Level.TRACE);
        }

        log.debug("Creating Inspector Manager...");
        InspectorManager im = new InspectorManager(config);
        im.inspectConnection("www.linux.com");


        // Only a little test with log4j2 and lambda expression
        log.trace("Running program in directory {} ", () ->  new File("").getAbsolutePath());
        log.debug("Shutting down");
    }



}
