package com.signicat.services.blockchain.rs;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Path("/static")
public class StaticResource {
    private static final Logger LOG = LogManager.getLogger(StaticResource.class);

    @GET
    @Path("{path:.*}")
    public Response getStaticFile(
            @PathParam("path") final String path,
            @HeaderParam("Accept") final String acceptHeader) throws IOException{
        final InputStream is = getClass().getClassLoader().getResourceAsStream("static/" + path);
        if (is == null) {
            LOG.info("Request for path " + path + " failed. Not found.");
            throw new NotFoundException("The requested file was not found.");
        }
        ;
        final String contentType = Files.probeContentType(new File(path).toPath());
/*
        final String contentType;
        try {
            contentType = URLConnection.guessContentTypeFromStream(is);
        } catch (final IOException e) {
            LOG.error("Requested static file " + path + " has unrecognizeable content type.", e);
            throw new ServerErrorException("Internal server error.", Response.Status.INTERNAL_SERVER_ERROR);
        }*/
        return Response.ok(is, contentType).build();
    }
}
