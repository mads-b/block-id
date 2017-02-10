package com.signicat.services.blockchain.rs;

import java.io.IOException;
import java.util.Objects;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.ServerErrorException;
import javax.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.signicat.services.blockchain.spi.Assertion;
import com.signicat.services.blockchain.spi.MasterKey;
import com.signicat.services.blockchain.spi.NodeNetwork;

/**
 * Endpoints communicated to using AJAX from static webpages hosted by {@link StaticResource},
 */
@Path("/chain")
public class MainResource {
    private static final Logger LOG = LogManager.getLogger(MainResource.class);

    private final NodeNetwork nodeNetwork;

    public MainResource(final NodeNetwork nodeNetwork) {
        this.nodeNetwork = Objects.requireNonNull(nodeNetwork);
    }

    @POST
    @Path("new")
    @Produces("application/json")
    public Response generateNewMasterKey() {
        final MasterKey masterKey;
        try {
            masterKey = new MasterKey();
        } catch (final IOException e) {
            LOG.error("Failed generating master key.", e);
            throw new ServerErrorException("Generating new master key failed.", Response.Status.INTERNAL_SERVER_ERROR);
        }

        try {
            nodeNetwork.pushMasterKey(masterKey);
        } catch (final IOException e) {
            LOG.error("Failed pushing master key to node network.", e);
            throw new ServerErrorException("Master key not accepted by node network or .", Response.Status.INTERNAL_SERVER_ERROR);
        }
        return Response.ok(masterKey.getValue()).build();
    }

    @POST
    @Path("authenticated")
    public Response tradeAuthenticationForMasterKey(final Assertion assertion) {
        try {
            return Response.ok(nodeNetwork.pushAssertion(assertion).getValue()).build();
        } catch (final IOException e) {
            LOG.error("Failed pushing assertion to node network.", e);
            throw new ServerErrorException("Failed while pushing assertion to node network :-(", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}