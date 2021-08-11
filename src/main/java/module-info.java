module FlyOnTheWallCatcher.main {
    // Based on https://www.baeldung.com/java-9-modularity and http://tutorials.jenkov.com/java/modules.html#automatic-modules
    requires transitive jdk.net;
    requires transitive info.picocli;
    requires org.apache.logging.log4j;

    exports org.terra.incognita.fotwc.cli;
    exports org.terra.incognita.fotwc.api;

    // Automatic modules
    requires static org.apache.logging.log4j.core;

}