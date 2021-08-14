// Copyright 2021 - David Pérez Serrada
package org.terra.incognita.fotwc.cli;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.terra.incognita.fotwc.api.InspectionStatus;
import org.terra.incognita.fotwc.api.InspectorManager;
import picocli.CommandLine;

import javax.management.*;
import java.io.File;
import java.lang.management.ManagementFactory;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;


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
     * Set log level
     */
    @CommandLine.Option(names = {"-l", "--logLevel"}, description = "Set log level" )
    private String logLevel = "INFO";

    private static String [][] expectedData = {
            // {"www.grc.com","7A:85:1C:F0:F6:9F:D0:CC:EA:EA:9A:88:01:96:BF:79:8C:E1:A8:33"},
            {"www.facebook.com","CD:B1:83:ED:D8:42:72:8B:78:9C:5E:AA:07:6B:07:95:A3:A2:B1:D2"},
            {"www.paypal.com","6D:6F:4F:70:A0:E3:EA:7B:60:DB:DC:1E:BE:2D:02:0A:AD:AF:C9:B7"},
            {"www.wikipedia.org","AF:B4:52:3F:79:51:A9:AD:F7:08:3E:66:B9:04:F6:26:6F:50:67:13"},
            {"twitter.com","D3:D6:3F:81:7C:78:6C:D5:4E:56:AF:DD:07:A2:30:7C:1E:33:AF:73"},
            // {"www.blogger.com","27:C6:60:5B:36:1A:5E:62:32:FB:2D:C7:31:CD:81:EF:AA:12:CD:CE"},
            {"www.linkedin.com","8D:99:7D:44:04:4A:3D:F9:1C:5E:FB:27:0B:4D:09:03:50:2C:AF:95"},
            {"www.yahoo.com","CF:2C:F3:6A:FE:6B:10:EC:44:77:C8:95:BB:96:2E:06:1F:0E:15:DA"},
            {"wordpress.com","7A:C1:B2:7E:09:FF:88:03:C3:E9:B7:4F:31:F4:AC:75:79:BA:66:E6"}
    };

    public static void main(final String... args) {
        log.atTrace().log("Init logging system");
        // Read the command line options
        Main config = CommandLine.populateCommand(new Main(), args);
        log.atTrace().log("Command line parameters parsed");

        log.atTrace().log("Command options, verbose: {}",config.logLevel);

        try {
            changeLogRootLevel(Level.toLevel(config.logLevel));
        } catch (JMException e) {
            log.atDebug().log("Failed setting root log level");
        }


        log.atDebug().log("Creating Inspector Manager...");
        InspectorManager im = new InspectorManager(config);
        Arrays.stream(expectedData).forEach( (data) -> {
            InspectionStatus.StatusCode statusCode = im.inspectConnection(data[0],data[1]);
            if ( statusCode != null ) {
                switch (statusCode) {
                    case EAVESDROP_DETECTED:
                        log.atError().log("EAVESDROP DETECTED IN DOMAIN {} ", () -> data[0]);
                        break;
                    case EAVESDROP_WARNING:
                        log.atWarn().log("WARNING AT DOMAIN %s ", () -> data[0]);
                        break;
                    case NO_EAVESDROP_DETECTED:
                        log.atInfo().log("NOT EAVESDROP DETECTED WHEN CONNECTING TO DOMAIN: {}, fingerpint: {} ", data[0], data[1]);
                        break;
                }
            }
        });



        // Only a little test with log4j2 and lambda expression
        log.atTrace().log("Running program in directory {} ", () ->  new File("").getAbsolutePath());
        log.atTrace().log("Shutting down");
    }

    private static void changeLogRootLevel(Level logLevel) throws JMException {
        // Configurator.setRootLevel(config.logLevel);
         MBeanServer server = ManagementFactory.getPlatformMBeanServer();

        Set<ObjectInstance> instances = server.queryMBeans(new ObjectName("org.apache.logging.log4j2:type=*,component=Loggers,name="), null);

        Iterator<ObjectInstance> iterator = instances.iterator();

        if (iterator.hasNext()) {
            ObjectInstance instance = iterator.next();
            server.setAttribute(instance.getObjectName(),new Attribute("Level",logLevel.toString()));
        }
    }


}
