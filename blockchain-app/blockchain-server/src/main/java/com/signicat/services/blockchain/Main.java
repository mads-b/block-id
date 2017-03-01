package com.signicat.services.blockchain;

import java.awt.Desktop;
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
        properties = new Properties();
        properties.put("http.port", "1337");
        properties.put("drain.file.directory", "/var/run");
        properties.put("metrics.context.name", "blockchain");
        properties.put("graphite.address", "localhost:9109");
        properties.put("graphite.polling_period_seconds", 30);
        properties.put("base.uri", "http://localhost:1337/");
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
            Desktop.getDesktop().browse(URI.create("http://localhost:1337/static/index.html"));
        } catch (final IOException e) {
            e.printStackTrace();
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
