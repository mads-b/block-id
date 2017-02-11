package com.signicat.services.blockchain.spi;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Memory-only implementation of a node network..
 */
public class DummyNodeNetwork implements NodeNetwork {
    private static final Logger LOG = LogManager.getLogger(NodeNetwork.class);

    private final Map<String, MasterKey> keys = new HashMap<>();
    private final Map<String, ClientSignedAssertion> assertionMap = new HashMap<>();

    @Override
    public void pushMasterKey(final MasterKey masterKey) throws IOException {
        keys.put(masterKey.getKeyId(), new MasterKey(masterKey.getKeyId(), masterKey.getPublicKey(), masterKey.getSplitPrivateKey(10, 15)));
    }

    @Override
    public MasterKey pushAssertion(final Assertion assertion) throws IOException {

        final String subjectId;
        try {
            subjectId = assertion.getJwt().getJWTClaimsSet().getSubject();
        } catch (final ParseException e) {
            throw new IOException("Failed when deserializing stored assertion.");
        }
        final String keyId = assertionMap.get(subjectId).getJWT().getHeader().getKeyID();
        LOG.info("Got assertion from subject " + subjectId + " and fetching master key with ID " + keyId);
        return keys.get(keyId);
    }

    @Override
    public void pushAssertion(final ClientSignedAssertion assertion) throws IOException {
        final String subjectId;
        try {
            final JWTClaimsSet claims = assertion.getJWT().getJWTClaimsSet();
            final JWSHeader header = JWSHeader.parse(claims.getJSONObjectClaim("header").toJSONString());
            final JWTClaimsSet payload = JWTClaimsSet.parse(claims.getJSONObjectClaim("payload"));
            final SignedJWT wrappedAssertion = new SignedJWT(header, payload);
            subjectId = wrappedAssertion.getJWTClaimsSet().getSubject();
        } catch (final ParseException e) {
            throw new IOException("Corrupt assertion..", e);
        }
        LOG.info("Subject ID " + subjectId + " is now known to the blockchain.");
        assertionMap.put(subjectId, assertion);
    }

    @Override
    public List<String> listBlockIds(final MasterKey masterKey) throws IOException {
        return null;
    }

    @Override
    public Assertion getBlock(final MasterKey masterKey, final String blockId) throws IOException {
        return null;
    }
}
