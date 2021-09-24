module FlyOnTheWallCatcher.main {
    // Based on https://www.baeldung.com/java-9-modularity,
    // http://tutorials.jenkov.com/java/modules.html#automatic-modules
    // https://mariocod.es/certifications/java/modules-11.html
    requires transitive jdk.net;
    requires jdk.management;
    requires transitive info.picocli;
    requires transitive org.apache.logging.log4j;

    // log4j implementation
    // if set jpackage fails, if not set jpackage works but the applications fails
    // because it is no included the required library
    // requires org.apache.logging.log4j.core;

    exports org.terra.incognita.fotwc.cli;
    exports org.terra.incognita.fotwc.api;

    // The cli preprocessor needs to access to configuration class file
    opens org.terra.incognita.fotwc.cli to info.picocli;

}