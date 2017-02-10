package com.signicat.services.blockchain.spi;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.KeyGenerator;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.signicat.services.blockchain.crypto.HKDF;

public class AssertionTest {
    private MasterKey masterKey;
    private byte[] tKey;
    private byte[] mtKey;
    private KeyPair idpKeys;
    private final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer("https://signicat.com")
            .subject("Alice")
            .claim("encryptThis", "claimValue")
            .build();
    private Assertion assertion;

    @Before
    public void geneateKeys() throws Exception {
        masterKey = new MasterKey();
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        // Key length anarchy!
        keyGen.init(128);
        tKey = keyGen.generateKey().getEncoded();
        mtKey = HKDF.hkdfExpand(HKDF.hkdfExtract(tKey, masterKey.getPrivateKey().getEncoded()), new byte[] {}, 256);
        final KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(512);
        idpKeys = keyPairGen.generateKeyPair();
        assertion = new Assertion(claimsSet, mtKey, tKey, idpKeys.getPrivate());
    }

    @Test
    public void canCreateEncryptAndSignAssertion() throws IOException {
        assertThat(assertion, is(notNullValue()));
        assertion.validateIdPSignature(idpKeys.getPublic());
    }

    @Test
    public void canDecryptValues() throws IOException {
        final Assertion assertion = new Assertion(claimsSet, mtKey, tKey, idpKeys.getPrivate());
        assertThat(
                assertion.decryptClaims(mtKey).getClaim("encryptThis"),
                is("claimValue"));
    }

    @Test
    public void serializeDeserialize() throws Exception {
        final ObjectMapper om = new ObjectMapper();
        assertThat(om.readValue(om.writeValueAsString(assertion), Assertion.class), is(assertion));
    }
}
