package com.signicat.services.blockchain.spi;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;
import com.google.common.collect.ImmutableList;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.signicat.services.blockchain.crypto.KeyShard;
import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;

import sun.security.rsa.RSAPublicKeyImpl;

/**
 * This class extends DummyNodeNetwork so it's possible to stub out any method with a dummy
 * one for testing.
 */
public class TrueNodeNetwork extends DummyNodeNetwork {
    private static final Logger LOG = LogManager.getLogger(TrueNodeNetwork.class);

    private static final List<URI> NODES = ImmutableList.of(
            URI.create("http://146.185.128.250:9000/"),
            URI.create("http://37.139.20.249:9000/")
    );


    @Override
    public void pushMasterKey(final MasterKey masterKey) throws IOException {
        final KeyShard[] shards = masterKey.getSplitPrivateKey(NODES.size(), NODES.size());
        final ObjectMapper mapper = new ObjectMapper();
        for (int i=0;i<NODES.size();i++) {
            ClientBuilder.newClient()
                    .register(JacksonJsonProvider.class)
                    .target(NODES.get(i))
                    .path("masterkeypart")
                    .request()
                    .post(Entity.json(new NodeNetworkShardFormat(
                            masterKey.getKeyId(),
                            mapper.writeValueAsString(shards[i]),
                            Base64URL.encode(masterKey.getPublicKey().getEncoded()).toJSONString())));
        }
    }

    @Override
    public void pushAssertion(final ClientSignedAssertion assertion) throws IOException {
        LOG.info(assertion.getValue());
        final String subjectId;
        try {
            final JWTClaimsSet claims = assertion.getJWT().getJWTClaimsSet();
            final JWSHeader header = JWSHeader.parse(claims.getJSONObjectClaim("header").toJSONString());
            final JWTClaimsSet payload = JWTClaimsSet.parse(claims.getJSONObjectClaim("payload"));
            final SignedJWT wrappedAssertion = new SignedJWT(header, payload);
            subjectId = wrappedAssertion.getJWTClaimsSet().getSubject();
            for (int i=0;i<NODES.size();i++) {
                final Response res = ClientBuilder.newClient()
                        .register(JacksonJsonProvider.class)
                        .target(NODES.get(i))
                        .path("assertion")
                        .request()
                        .post(Entity.text(assertion.getValue()));
                LOG.info("Got this: " + res.readEntity(String.class));
            }
        } catch (final ParseException e) {
            throw new IOException("Corrupt assertion..", e);
        }
        LOG.info("Subject ID " + subjectId + " is now known to the blockchain.");
    }

    @Override
    public MasterKey pushAssertion(final Assertion assertion) throws IOException {
        final ObjectMapper mapper = new ObjectMapper();
        final List<KeyShard> masterKeyShards = new ArrayList<>();
        String keyId = null;
        LOG.info("Sending: " + assertion.getValue());
        RSAPublicKey pubKey = null;
        for (int i=0;i<NODES.size();i++) {
            final String res = ClientBuilder.newClient()
                    .register(JacksonJsonProvider.class)
                    .target(NODES.get(i))
                    .path("assertion/trade")
                    .request(MediaType.APPLICATION_JSON)
                    .post(Entity.text(assertion.getValue()))
                    .readEntity(String.class);
            LOG.info("got this: " + res);
            final NodeNetworkShardFormat keyShard = mapper.readValue(res, NodeNetworkShardFormat.class);
            masterKeyShards.add(mapper.readValue(keyShard.privateKeyPart, KeyShard.class));
            try {
                keyId = keyShard.getKeyId();
                pubKey = new RSAPublicKeyImpl(new Base64URL(keyShard.publicKey).decode());
            } catch (final InvalidKeyException e) {
                LOG.error("Key is corrupt :-(", e);
            }
        }
        return new MasterKey(keyId, pubKey, masterKeyShards.toArray(new KeyShard[masterKeyShards.size()]));
    }

    @Override
    public List<String> listBlockIds(final MasterKey masterKey) throws IOException {
        final String res = ClientBuilder.newClient()
                .register(JacksonJsonProvider.class)
                .target(NODES.get(0))
                .path("blocks")
                .path(masterKey.getKeyId())
                .request(MediaType.APPLICATION_JSON)
                .get()
                .readEntity(String.class);
        final ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(res, new TypeReference<List<String>>() {});
    }

    @Override
    public Assertion getBlock(final MasterKey masterKey, final String blockId) throws IOException {
        final String res = ClientBuilder.newClient()
                .register(JacksonJsonProvider.class)
                .target(NODES.get(0))
                .path("block")
                .path(blockId)
                .request()
                .get()
                .readEntity(String.class);
        LOG.info("Got assertion: " + res);
        final ClientSignedAssertion ass;
        try {
            ass = ClientSignedAssertion.valueOf(res);
        } catch (final ParseException e) {
            LOG.error("Got corrupt assertion from the blockchain", e);
            throw new IOException("Got corrupt assertion from the blockchain", e);
        }
        final PublicKey pubKey = masterKey != null ? masterKey.getPublicKey() : null;
        return ass.getAssertion(pubKey);
    }

    private static class NodeNetworkShardFormat {
        private final String keyId;
        private final String privateKeyPart;
        private final String publicKey;

        @JsonCreator
        public NodeNetworkShardFormat(
                @JsonProperty("id") final String keyId,
                @JsonProperty("privateKeyPart") final String privateKeyPart,
                @JsonProperty("publicKey") final String publicKey) {
            this.keyId = keyId;
            this.privateKeyPart = privateKeyPart;
            this.publicKey = publicKey;
        }

        @JsonProperty("id")
        public String getKeyId() {
            return keyId;
        }

        @JsonProperty("privateKeyPart")
        public String getPrivateKeyPart() {
            return privateKeyPart;
        }

        @JsonProperty("publicKey")
        public String getPublicKey() {
            return publicKey;
        }
    }

}
