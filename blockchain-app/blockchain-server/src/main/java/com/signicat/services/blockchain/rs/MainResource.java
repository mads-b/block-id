package com.signicat.services.blockchain.rs;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.ServerErrorException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.signicat.services.blockchain.crypto.HKDF;
import com.signicat.services.blockchain.spi.Assertion;
import com.signicat.services.blockchain.spi.ClientSignedAssertion;
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
    @Path("derivekey")
    @Produces("application/json")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response deriveMtKey(
            @FormParam("masterkey") final MasterKey masterKey,
            @FormParam("t") final String salt) {
        final OctetSequenceKey mtKey = new OctetSequenceKey.Builder(HKDF.hkdfExpand(HKDF.hkdfExtract(
                salt.getBytes(), masterKey.getPrivateKey().getEncoded()), new byte[]{}, masterKey.getPrivateKey().getEncoded().length))
                .build();
        return Response.ok(mtKey.toJSONObject().toJSONString()).build();

    }

    @POST
    @Path("authenticated")
    public Response associateIdpWithAccount(
            @FormParam("ass") final Assertion assertion,
            @FormParam("key") final MasterKey masterKey) {
        if (masterKey == null) {
            try {
                return Response.ok(nodeNetwork.pushAssertion(assertion).getValue()).build();
            } catch (final IOException e) {
                LOG.error("Failed pushing assertion to node network.", e);
                throw new ServerErrorException("Failed while pushing assertion to node network :-(", Response.Status.INTERNAL_SERVER_ERROR);
            }
        }

        try {
            nodeNetwork.pushAssertion(ClientSignedAssertion.createFromAssertion(masterKey, assertion));
            return Response.ok().build();
        } catch (final IOException e) {
            LOG.error("Failed pushing assertion to node network.", e);
            throw new ServerErrorException("Failed while pushing assertion to node network :-(", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("dumpdata")
    @Produces("application/json")
    public Response getAllData(@QueryParam("key") final MasterKey masterKey) {
        try {
            final List<String> blockIds = nodeNetwork.listBlockIds(masterKey);
            final Map<String, Object> data = new HashMap<>();
            for (final String blockId : blockIds) {
                final Assertion assertion = nodeNetwork.getBlock(masterKey, blockId);
                final String tKey = assertion.getJwt().getJWTClaimsSet().getStringClaim("t");
                final OctetSequenceKey mtKey = OctetSequenceKey.parse((String)deriveMtKey(masterKey, tKey).getEntity());
                final JWTClaimsSet claims = assertion.decryptClaims(mtKey.toByteArray());
                data.putAll(claims.getClaims());
            }
            return Response.ok(new ObjectMapper().writeValueAsString(data)).build();
        } catch (final IOException | ParseException e) {
            LOG.error("Failed fetching blocks.", e);
            throw new ServerErrorException("Failed while pushing assertion to node network :-(", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}
