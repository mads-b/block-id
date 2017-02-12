package com.signicat.services.blockchain;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.util.Properties;

import javax.ws.rs.core.UriBuilder;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.server.Server;
import org.glassfish.jersey.jetty.JettyHttpContainerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import com.signicat.services.blockchain.rs.MainResource;
import com.signicat.services.blockchain.rs.StaticResource;
import com.signicat.services.blockchain.spi.DummyNodeNetwork;
import com.signicat.services.blockchain.spi.TrueNodeNetwork;

/**
 * Main entry point for server.
 */
public class Main {
    public static final Clock CLOCK = Clock.systemUTC();
    private static final Logger LOG = LogManager.getLogger(Main.class.getName());

    private final Properties properties;
    private final Server server;

    public static void main(final String[] args) {
        try {
            new Main(args).start();
        } catch (final Exception e) {
            LOG.error("Bootstrapping server failed..", e);
        }
    }

    public Main(final String[] args) {
        if (args.length != 1) {
            throw new RuntimeException("Need ONE parameter only (path to properties file)!");
        }
        final String propertiesFilePath = args[0];
        final File file = new File(propertiesFilePath);
        properties = new Properties();
        try {
            properties.load(new FileInputStream(file));
        } catch (IOException e) {
            throw new RuntimeException("File named "
                    + file.getAbsolutePath()
                    + " does not exist or is not readable.", e);
        }
        URI baseUri = UriBuilder
                .fromUri("http://localhost/")
                .port(Integer.parseInt(properties.getProperty("http.port")))
                .build();
        server = JettyHttpContainerFactory.createServer(baseUri, createResourceConfig());
    }

    public ResourceConfig createResourceConfig() {
        LOG.info("Bootstrapping Blockchain Client");
        return new ResourceConfig()
                .register(new StaticResource())
                .register(new MainResource(new TrueNodeNetwork()));
    }

    public void start() {
        try {
            server.start();
        } catch (final Exception e) {
            LOG.warn("Got exception while starting Jetty Server.", e);
        }
        try {
            server.join();
        } catch (final InterruptedException e) {
            LOG.info("Interrupted while joining server. Might not be shut down correctly.", e);
        }
        try {
            server.stop();
        } catch (final Exception e) {
            LOG.info(
                    "Got exception while stopping Jetty Server. Ah, who cares. Do a kill -9 or whatever.",
                    e);
        }
    }
}
