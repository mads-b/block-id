package com.signicat.services.blockchain.rs;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.signicat.services.blockchain.crypto.HKDF;
import com.signicat.services.blockchain.spi.Assertion;
import com.signicat.services.blockchain.spi.ClientSignedAssertion;
import com.signicat.services.blockchain.spi.MasterKey;
import com.signicat.services.blockchain.spi.NodeNetwork;

import net.minidev.json.JSONObject;

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
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
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
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllData(@QueryParam("key") final MasterKey masterKey) {
        try {
            final List<String> blockIds = nodeNetwork.listBlockIds(masterKey);
            final List<Map<String, Object>> data = new ArrayList<>();
            for (final String blockId : blockIds) {
                final Assertion assertion = nodeNetwork.getBlock(masterKey, blockId);
                final String tKey = assertion.getJwt().getJWTClaimsSet().getStringClaim("t");
                final OctetSequenceKey mtKey = OctetSequenceKey.parse((String)deriveMtKey(masterKey, tKey).getEntity());
                final JWTClaimsSet claims = assertion.decryptClaims(mtKey.toByteArray());
                data.add(claims.getClaims());
            }
            return Response.ok(new ObjectMapper().writeValueAsString(data)).build();
        } catch (final IOException | ParseException e) {
            LOG.error("Failed fetching blocks.", e);
            throw new ServerErrorException("Failed while pushing assertion to node network :-(", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("claimkeys")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response generateKeys(
            @FormParam("key") final MasterKey key,
            @FormParam("claims") final String claimsString) {
        try {
            final ObjectMapper mapper = new ObjectMapper();
            final List<String> claims = mapper.readValue(claimsString, List.class);
            final List<String> blockIds = nodeNetwork.listBlockIds(key);
            final Map<String, Pair> claimNameToKeys = new HashMap<>();

            for (final String blockId : blockIds) {
                final Assertion assertion = nodeNetwork.getBlock(key, blockId);
                final String tKey = assertion.getJwt().getJWTClaimsSet().getStringClaim("t");
                final OctetSequenceKey mtKey = OctetSequenceKey.parse((String) deriveMtKey(key, tKey).getEntity());
                for (final String claim : claims) {
                    if (assertion.getJwt().getJWTClaimsSet().getClaim(claim) != null) {
                        final OctetSequenceKey claimKey = new OctetSequenceKey.Builder(Assertion.makeClaimKey(mtKey.toByteArray(), claim)).build();
                        claimNameToKeys.put(claim, new Pair(claimKey.toJSONObject(), blockId));
                    }
                }
            }
            LOG.info("Master key: " + key.getValue() + " Claims: " + claims.toString());
            return Response.ok(mapper.writeValueAsString(claimNameToKeys)).build();
        } catch(final ParseException | IOException e){
            LOG.error("Failed while generating Claim Keys", e);
            throw new ServerErrorException("Failed while creating Claim Keys :-(", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Path("decryptclaims")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response decrypt(@FormParam("keys") String keysString) throws IOException {
        final ObjectMapper mapper = new ObjectMapper();

        final Map<String, Pair> keys = mapper.readValue(keysString, new TypeReference<Map<String, Pair>>() {});
        final Map<String, String> decryptedClaims = new HashMap<>();
        for (final Map.Entry<String, Pair> key : keys.entrySet()) {
            final Assertion ass = nodeNetwork.getBlock(null, key.getValue().blockId);
            try {
                decryptedClaims.put(key.getKey(), ass.decryptClaim(key.getKey(), OctetSequenceKey.parse(key.getValue().getKey()).toByteArray(), String.class));
            } catch (final ParseException e) {
                LOG.error("Failed parsing key of claim " + key.getKey(), e);
                throw new ServerErrorException("I failed miserably :-(", Response.Status.INTERNAL_SERVER_ERROR);
            }
        }
        return Response.ok(mapper.writeValueAsString(decryptedClaims)).build();
    }



    private static class Pair {
        private final JSONObject key;
        private final String blockId;

        @JsonCreator
        public Pair(@JsonProperty("key") final JSONObject key, @JsonProperty("block_id") final String blockId) {
            this.key = key;
            this.blockId = blockId;
        }

        @JsonProperty("key")
        public JSONObject getKey() {
            return key;
        }

        @JsonProperty("block_id")
        public String getBlockId() {
            return blockId;
        }

    }
}
