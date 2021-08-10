module FlyOnTheWallCatcher.main {
    // Based on https://www.baeldung.com/java-9-modularity
    requires transitive jdk.net;
    requires transitive org.apache.logging.log4j;
    requires transitive org.apache.logging.log4j.core;
    requires transitive info.picocli;
    exports org.terra.incognita.fotwc.cli;
}